/* cgmanager
 *
 * Copyright © 2013 Serge Hallyn
 * Author: Serge Hallyn <serge.hallyn@ubuntu.com>
 *
 * based on cgroup.c from
 * lxc: linux Container library
 * (C) Copyright IBM Corp. 2007, 2008
 * Authors:
 * Daniel Lezcano <daniel.lezcano at free.fr>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/param.h>
#include <stdbool.h>

#include <nih/macros.h>
#include <nih/alloc.h>
#include <nih/string.h>
#include <nih/io.h>
#include <nih/option.h>
#include <nih/main.h>
#include <nih/logging.h>
#include <nih/error.h>

#include <nih-dbus/dbus_connection.h>
#include <nih-dbus/dbus_proxy.h>

struct controller_mounts {
	char *controller;
	char *options;
	char *path;
};

static struct controller_mounts *all_mounts;
static int num_controllers;

static char *base_path;
/*
 * Where do we want to mount the controllers?  We used to mount
 * them under a tmpfs under /sys/fs/cgroup, for all to share.  Now
 * we want to have our socket there.  So how about /run/cgmanager/fs?
 * TODO read this from configuration file too
 * TODO do we want to create these in a tmpfs?
 */
static bool setup_base_path(void)
{
	base_path = strdup("/run/cgmanager/fs");
	if (!base_path)
		return false;
	if (mkdir("/run", 0755) < 0 && errno != EEXIST) {
		nih_fatal("failed to create /run");
		return false;
	}
	if (mkdir("/run/cgmanager", 0755) < 0 && errno != EEXIST) {
		nih_fatal("failed to create /run/cgmanager");
		return false;
	}
	if (mkdir("/run/cgmanager/fs", 0755) < 0 && errno != EEXIST) {
		nih_fatal("failed to create /run/cgmanager/fs");
		return false;
	}
	return true;
}

static void set_clone_children(const char *path)
{
	char p[MAXPATHLEN];
	FILE *f;
	int ret;

	ret = snprintf(p, MAXPATHLEN, "%s/cgroup.clone_children", path);
	if (ret < 0 || ret >= MAXPATHLEN)
		return;
	f = fopen(p, "w");
	if (!f) {
		nih_fatal("Failed to set memory.use_hierarchy");
		return;
	}
	fprintf(f, "1\n");
	fclose(f);
}

static void set_use_hierarchy(const char *path)
{
	char p[MAXPATHLEN];
	FILE *f;
	int ret;

	ret = snprintf(p, MAXPATHLEN, "%s/memory.use_hierarchy", path);
	if (ret < 0 || ret >= MAXPATHLEN)
		return;
	f = fopen(p, "w");
	if (!f) {
		nih_fatal("Failed to set memory.use_hierarchy");
		return;
	}
	fprintf(f, "1\n");
	fclose(f);
}

/**
 * Mount the cgroup filesystems and record the information.
 * This should take configuration data from /etc.  For now,
 * Just mount all controllers, separately just as cgroup-lite
 * does, and set the use_hierarchy and clone_children options.
 *
 * Things which should go into configuration file:
 * . which controllers to mount
 * . which controllers to co-mount
 * . any mount options (per-controller)
 * . values for sane_behavior, use_hierarchy, and clone_children
 */
int setup_cgroup_mounts(void)
{
	FILE *cgf;
	int ret, len=0;
	char line[400];

	if (unshare(CLONE_NEWNS) < 0) {
		nih_fatal("Failed to unshare a private mount ns: %s", strerror(errno));
		return -1;
	}
	if (!setup_base_path()) {
		nih_fatal("Error setting up base cgroup path");
		return -1;
	}
	if ((cgf = fopen("/proc/cgroups", "r")) == NULL) {
		nih_fatal ("Error opening /proc/cgroups: %s", strerror(errno));
		return -1;
	}
	while (fgets(line, 400, cgf)) {
		char *p, *p2;
		struct controller_mounts *tmp;
		char dest[MAXPATHLEN];
		unsigned long h;

		if (line[0] == '#')
			continue;
		p = index(line, '\t');
		if (!p)
			continue;
		*p = '\0';
		h = strtoul(p+1, NULL, 10);
		if (h) {
			nih_info("%s was already mounted!", line);
#if STRICT
			ret = -1;
			goto out;
#endif
		}
		ret = snprintf(dest, MAXPATHLEN, "%s/%s", base_path, line);
		if (ret < 0 || ret >= MAXPATHLEN) {
			nih_fatal("Error calculating pathname for %s and %s", base_path, line);
			goto out;
		}
		if (mkdir(dest, 0755) < 0 && errno != EEXIST) {
			nih_fatal("Failed to create %s: %s", dest, strerror(errno));
			ret = -1;
			goto out;
		}
		if ((ret = mount(line, dest, "cgroup", 0, line)) < 0) {
			nih_fatal("Failed mounting %s: %s", line, strerror(errno));
			goto out;
		}
		ret = -1;
		tmp = realloc(all_mounts, (num_controllers+1) * sizeof(*all_mounts));
		if (!tmp) {
			nih_fatal("Out of memory mounting controllers");
			goto out;
		}
		all_mounts = tmp;
		all_mounts[num_controllers].controller = strdup(line);
		if (!all_mounts[num_controllers].controller) {
			nih_fatal("Out of memory mounting controllers");
			goto out;
		}
		all_mounts[num_controllers].options = NULL;
		all_mounts[num_controllers].path = strdup(dest);
		if (!all_mounts[num_controllers].path) {
			nih_fatal("Out of memory mounting controllers");
			goto out;
		}
		nih_info("Mounted %s onto %s",
			all_mounts[num_controllers].controller,
			all_mounts[num_controllers].path);
		if (strcmp(all_mounts[num_controllers].controller, "cpuset") == 0) {
			set_clone_children(dest); // TODO make this optional?
		} else if (strcmp(all_mounts[num_controllers].controller, "memory") == 0) {
			set_use_hierarchy(dest);  // TODO make this optional?
		}
		num_controllers++;
	}
	nih_info("mounted %d controllers", num_controllers);
	ret = 0;
out:
	fclose(cgf);
	return ret;
}

static inline void drop_newlines(char *s)
{
	int l;

	while ((l=strlen(s)) > 0 && s[l-1] == '\n')
		s[l-1] = '\0';
}

#define min(x, y) (x > y ? y : x)
static inline char *pid_cgroup(pid_t pid, const char *controller, char *retv)
{
	FILE *f;
	char path[100];
	char *line = NULL, *cgroup = NULL;
	size_t len = 0;

	sprintf(path, "/proc/%d/cgroup", (int) pid);
	if ((f = fopen(path, "r")) == NULL) {
		nih_fatal("could not open cgroup file for %d", (int) pid);
		return NULL;
	}
	while (getline(&line, &len, f) != -1) {
		char *c1, *c2;
		char *token, *saveptr = NULL;
		if ((c1 = index(line, ':')) == NULL)
			continue;
		if ((c2 = index(++c1, ':')) == NULL)
			continue;
		*c2 = '\0';
		for (; (token = strtok_r(c1, ",", &saveptr)); c1 = NULL) {
			if (strcmp(token, controller) != 0)
				continue;
			if (strlen(c2+1) + 1 > MAXPATHLEN) {
				nih_fatal("cgroup name too long");
				goto found;
			}
			strncpy(retv, c2+1, strlen(c2+1)+1);
			drop_newlines(retv);
			cgroup = retv;
			goto found;
		}
	}
found:
	fclose(f);
	free(line);
	return cgroup;
}

/*
 * Given host @uid, return the uid to which it maps in
 * the namespace, or -1 if none.
 */
static uid_t hostuid_to_ns(uid_t uid, pid_t pid)
{
	FILE *f;
	int ret, nsuid, hostuid, count;
	char line[400];

	sprintf(line, "/proc/%d/uid_map", (int)pid);
	if ((f = fopen(line, "r")) == NULL) {
		return -1;
	}
	while (fgets(line, 400, f)) {
		ret = sscanf(line, "%d %d %d\n", &nsuid, &hostuid, &count);
		if (ret != 3)
			continue;
		if (hostuid <= uid && hostuid+count > uid) {
			fclose(f);
			return (uid - hostuid) + nsuid;
		}
	}
	fclose(f);
	return -1;
}

/*
 * pid may access path if the uids are the same, or if
 * path's uid is mapped into the userns and pid is root
 * there, or if the gids are the same and path has mode
 * in group rights, or if path has mode in other rights.
 *
 * uid and gid are passed in to avoid recomputation.
 */
bool may_access(pid_t pid, uid_t uid, gid_t gid, const char *path, int mode)
{
	struct stat sb;
	int ret;

	ret = stat(path, &sb);
	if (ret < 0) {
		nih_fatal("Could not look up %s\n", path);
		return false;
	}
	if (uid == sb.st_uid) {
		if (mode == O_RDONLY && sb.st_mode & S_IRUSR)
			return true;
		if (mode == O_RDWR && ((sb.st_mode & (S_IRUSR|S_IWUSR)) == (S_IRUSR|S_IWUSR)))
			return true;
		if (mode == O_WRONLY && sb.st_mode & S_IWUSR)
			return true;
	}
	if (gid == sb.st_gid) {
		if (mode == O_RDONLY && sb.st_mode & S_IRGRP)
			return true;
		if (mode == O_RDWR && ((sb.st_mode & (S_IRGRP|S_IWGRP)) == (S_IRGRP|S_IWGRP)))
			return true;
		if (mode == O_WRONLY && sb.st_mode & S_IWGRP)
			return true;
	}
	if (hostuid_to_ns(uid, pid) == 0 && hostuid_to_ns(sb.st_uid, pid) != -1)
		return true;

	if (mode == O_RDONLY && sb.st_mode & S_IROTH)
		return true;
	if (mode == O_RDWR && ((sb.st_mode & (S_IROTH|S_IWOTH)) == (S_IROTH|S_IWOTH)))
		return true;
	if (mode == O_WRONLY && sb.st_mode & S_IWOTH)
		return true;
	return false;
}

const char *get_controller_path(const char *controller)
{
	int i;

	for (i=0; i<num_controllers; i++) {
		if (strcmp(all_mounts[i].controller, controller) == 0)
			return all_mounts[i].path;
	}
	return NULL;
}

/*
 * Calculate a full path to the cgroup being requested.
 * @pid is the process making the request
 * @controller is the mounted controller under which we will look.
 * @cgroup is the cgroup which @pid is asking about.  If @cgroup is
 * @path is the path in which to return the full cgroup path.
 *    "a/b", then we concatenate "/cgroup/for/pid" with "a/b"
 *    If @cgroup is "/a/b", then we use "/a/b"
 */
bool compute_pid_cgroup(pid_t pid, const char *controller, const char *cgroup, char *path)
{
	int ret;
	char requestor_cgpath[MAXPATHLEN], fullpath[MAXPATHLEN], *cg;
	const char *cont_path;
	bool abspath = false;

	if (cgroup && cgroup[0] != '/') {
		cg = pid_cgroup(pid, controller, requestor_cgpath);
		if (!cg) {
			return false;
		}
	} else
		abspath = true;

	if ((cont_path = get_controller_path(controller)) == NULL) {
		nih_fatal("Controller %s not mounted", controller);
		return false;
	}

	/* append the requested cgroup */
	ret = snprintf(fullpath, MAXPATHLEN, "%s/%s%s%s", cont_path,
			abspath ? "" : cg, abspath ? "" : "/",
			cgroup ? cgroup : "");
	if (ret < 0 || ret >= MAXPATHLEN) {
		nih_fatal("Path name too long: %s/%s/%s", cont_path, cg, cgroup);
		return false;
	}

	/* Make sure client isn't passing us a bunch of bogus '../'s to
	 * try to read host files */
	if (!realpath(fullpath, path)) {
		nih_fatal("Invalid path %s", fullpath);
		return false;
	}
	if (strncmp(path, cont_path, strlen(cont_path)) != 0) {
		nih_fatal("invalid cgroup path '%s' for pid %d", cgroup, (int)pid);
		return false;
	}

	return true;
}

char *file_read_string(const char *path)
{
	int ret, fd = open(path, O_RDONLY);
	char *string = NULL;
	off_t sz = 0;
	if (fd < 0) {
		nih_fatal("Error opening %s: %s", path, strerror(errno));
		return NULL;
	}

	while (1) {
		char *n;
		sz += 1024;
		if (!(n = realloc(string, sz))) {
			free(string);
			string = NULL;
			goto out;
		}
		string = n;
		memset(string+sz-1024, 0, 1024);
		ret = read(fd, string+sz-1024, 1024);
		if (ret < 0) {
			free(string);
			string = NULL;
			goto out;
		}
		if (ret < 1024)
			break;
	}
out:
	close(fd);
	return string;
}

void get_pid_creds(pid_t pid, uid_t *uid, gid_t *gid)
{
	char line[400];
	int ret, u, g;
	FILE *f;

	*uid = -1;
	*gid = -1;
	sprintf(line, "/proc/%d/status", (int)pid);
	if ((f = fopen(line, "r")) == NULL) {
		nih_fatal("Error opening %s: %s", line, strerror(errno));
		return;
	}
	while (fgets(line, 400, f)) {
		if (strncmp(line, "Uid:", 4) == 0) {
			if (sscanf(line+4, "%d", &u) != 1) {
				nih_fatal("bad uid line for pid %d", (int)pid);
				fclose(f);
				return;
			}
			*uid = (uid_t)u;
		} else if (strncmp(line, "Gid:", 4) == 0) {
			if (sscanf(line+4, "%d", &g) != 1) {
				nih_fatal("bad gid line for pid %d", (int)pid);
				fclose(f);
				return;
			}
			*gid = (uid_t)g;
		}
	}
	fclose(f);
}
