/*
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
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <sys/param.h>
#include <stdbool.h>
#include <dirent.h>

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
		nih_fatal("Failed to set clone_children");
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
	int ret;
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
		char *p;
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
			ret = -1;
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
			nih_info("set clone_children");
		} else if (strcmp(all_mounts[num_controllers].controller, "memory") == 0) {
			set_use_hierarchy(dest);  // TODO make this optional?
			nih_info("set memory.use_hierarchy");
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

	for (l=strlen(s); l>0 && s[l-1] == '\n'; l--)
		s[l-1] = '\0';
}

/*
 * pid_cgroup: return the cgroup of @pid for @controller.
 * retv must be a (at least) MAXPATHLEN size buffer into
 * which the answer will be copied.
 */
static inline char *pid_cgroup(pid_t pid, const char *controller, char *retv)
{
	FILE *f;
	char path[100];
	char *line = NULL, *cgroup = NULL;
	size_t len = 0;

	sprintf(path, "/proc/%d/cgroup", (int) pid);
	if ((f = fopen(path, "r")) == NULL) {
		nih_error("could not open cgroup file for %d", (int) pid);
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
				nih_error("cgroup name too long");
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
 * @pid's user namespace, or -1 if none.
 */
uid_t hostuid_to_ns(uid_t uid, pid_t pid)
{
	FILE *f;
	uid_t nsuid, hostuid;
	unsigned int count;
	char line[400];
	int ret;

	sprintf(line, "/proc/%d/uid_map", (int)pid);
	if ((f = fopen(line, "r")) == NULL) {
		return -1;
	}
	while (fgets(line, 400, f)) {
		ret = sscanf(line, "%u %u %u\n", &nsuid, &hostuid, &count);
		if (ret != 3)
			continue;
		if (hostuid + count < hostuid || nsuid + count < nsuid) {
			/*
			 * uids wrapped around - unexpected as this is a procfile,
			 * so just bail.
			 */
			nih_error("pid wrapparound at entry %u %u %u in %s",
				nsuid, hostuid, count, line);
			break;
		}
		if (hostuid <= uid && hostuid+count > uid) {
			/*
			 * now since hostuid <= uid < hostuid+count, and
			 * hostuid+count and nsuid+count do not wrap around,
			 * we know that nsuid+(uid-hostuid) which must be
			 * less that nsuid+(count) must not wrap around
			 */
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
 * uid and gid are passed in to avoid recomputation.  uid
 * and gid are the host uids, not mapped into the ns.
 */
bool may_access(pid_t pid, uid_t uid, gid_t gid, const char *path, int mode)
{
	struct stat sb;
	int ret;

	ret = stat(path, &sb);
	if (ret < 0) {
		nih_error("Could not look up %s\n", path);
		return false;
	}

	/* TODO - we should check capability set as well */
	if (uid == 0)
		return true;

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
		nih_error("Controller %s not mounted", controller);
		return false;
	}

	/* append the requested cgroup */
	ret = snprintf(fullpath, MAXPATHLEN, "%s/%s%s%s", cont_path,
			abspath ? "" : cg, abspath ? "" : "/",
			cgroup ? cgroup : "");
	if (ret < 0 || ret >= MAXPATHLEN) {
		nih_error("Path name too long: %s/%s/%s", cont_path, cg, cgroup);
		return false;
	}

	/* Make sure client isn't passing us a bunch of bogus '../'s to
	 * try to read host files */
	if (!realpath(fullpath, path)) {
		nih_error("Invalid path %s", fullpath);
		return false;
	}
	if (strncmp(path, cont_path, strlen(cont_path)) != 0) {
		nih_error("invalid cgroup path '%s' for pid %d", cgroup, (int)pid);
		return false;
	}

	return true;
}

/*
 * file_read_string:
 *
 * @parent: parent which will be given a reference to the returned string
 * (to allow the returned value to be freed automatically when @parent is
 * freed).
 * @path: Full path to file to read.
 *
 * Read specified file and return its contents.
 *
 * Returns: newly-allocated contents of file @path, or NULL on
 * insufficient memory.
 */
char *file_read_string(void *parent, const char *path)
{
	int ret, fd = open(path, O_RDONLY);
	char *string = NULL;
	off_t sz = 0;
	if (fd < 0) {
		nih_error("Error opening %s: %s", path, strerror(errno));
		return NULL;
	}

	while (1) {
		char *n;
		sz += 1024;
		if (!(n = nih_realloc(string, parent, sz))) {
			if (string)
				nih_free(string);
			string = NULL;
			goto out;
		}
		string = n;
		memset(string+sz-1024, 0, 1024);
		ret = read(fd, string+sz-1024, 1024);
		if (ret < 0) {
			nih_free(string);
			string = NULL;
			goto out;
		}
		if (ret < 1024)
			break;
	}
out:
	close(fd);
	if (string && *string)
		drop_newlines(string);
	return string;
}

/*
 * file_read_pids:
 *
 * @parent: parent which will be given a reference to the returned string
 * (to allow the returned value to be freed automatically when @parent is
 * freed).
 * @path: Full path to file to read.
 *
 * Read specified file and return the pids it contains.  The file is
 * expected to contain only a set of newline-separated int32_ts.
 *
 * Returns: Number of pids read, which are placed into the newly allocated
 * pids array (passed in).
 */
int file_read_pids(void *parent, const char *path, int32_t **pids)
{
	int nrpids = 0, pid;
	FILE *fin = fopen(path, "r");

	*pids = NULL;
	if (!fin) {
		nih_error("Error opening %s: %s", path, strerror(errno));
		return -1;
	}

	while (fscanf(fin, "%d", &pid) == 1) {
		int32_t *tmp;
		if (!(tmp = nih_realloc(*pids, parent, (nrpids+1)*sizeof(int32_t)))) {
			if (*pids)
				nih_free(*pids);
			pids = NULL;
			goto out;
		}
		*pids = tmp;
		(*pids)[nrpids++] = (int32_t) pid;
	}
out:
	fclose(fin);
	return nrpids;
}

/*
 * get_pid_creds: get the real uid and gid of @pid from
 * /proc/$$/status
 * (XXX should we use euid here?)
 */
void get_pid_creds(pid_t pid, uid_t *uid, gid_t *gid)
{
	char line[400];
	int u, g;
	FILE *f;

	*uid = -1;
	*gid = -1;
	sprintf(line, "/proc/%d/status", (int)pid);
	if ((f = fopen(line, "r")) == NULL) {
		nih_error("Error opening %s: %s", line, strerror(errno));
		return;
	}
	while (fgets(line, 400, f)) {
		if (strncmp(line, "Uid:", 4) == 0) {
			if (sscanf(line+4, "%d", &u) != 1) {
				nih_error("bad uid line for pid %d", (int)pid);
				fclose(f);
				return;
			}
			*uid = (uid_t)u;
		} else if (strncmp(line, "Gid:", 4) == 0) {
			if (sscanf(line+4, "%d", &g) != 1) {
				nih_error("bad gid line for pid %d", (int)pid);
				fclose(f);
				return;
			}
			*gid = (uid_t)g;
		}
	}
	fclose(f);
}

/*
 * Given a directory path, chown it to a userid.
 * We will chown $path and try to chown $path/tasks and $path/procs.
 * if @all_children is true, then chown all files under @path.  (This
 * is for the case where the caller had the rights to mkdir the path.
 * In that case he gets to write to all files - the kernel will ensure
 * hierarhical limits)
 *
 * Return true so long as we could chown the directory itself.
 */
bool chown_cgroup_path(const char *path, uid_t uid, gid_t gid, bool all_children)
{
	int len, ret;
	nih_local char *fpath = NULL;

	nih_assert (path);

	len = strlen(path);

	if (chown(path, uid, gid) < 0)
		return false;

	if (all_children) {
		struct dirent dirent, *direntp;
		char fpath[MAXPATHLEN];
		DIR *d;

		if (len >= MAXPATHLEN)
			return true;

		d = opendir(path);
		if (!d)
			goto out;

		strcpy(fpath, path);
		while (readdir_r(d, &dirent, &direntp) == 0 && direntp) {
			if (!strcmp(direntp->d_name, ".") || !strcmp(direntp->d_name, ".."))
				continue;
			ret = snprintf(fpath+len, MAXPATHLEN-len, "/%s", direntp->d_name);
			if (ret < 0 || ret >= MAXPATHLEN-len)
				continue;
			if (chown(fpath, uid, gid) < 0)
				nih_info("Failed to chown file %s to %d:%d",
					fpath, (int)uid, (int)gid);
		}
		closedir(d);
	} else {
		fpath = nih_sprintf(NULL, "%s/cgroup.procs", path);
		if (!fpath)
			return true;
		if (chown(fpath, uid, gid) < 0)
			nih_info("Failed to chown procs file %s", fpath);
		sprintf(fpath+len, "/tasks");
		if (chown(fpath, uid, gid) < 0)
			nih_info("Failed to chown tasks file %s", fpath);
	}

out:
	return true;
}

/*
 * TODO - make this more baroque to allow ranges etc
 */
static char *set_value_blacklist[] = { "tasks", "release-agent", "cgroup.procs" };
static size_t blacklist_len = sizeof(set_value_blacklist)/sizeof(char *);

bool set_value(const char *path, const char *value)
{
	int i, len;
	FILE *f;

	nih_assert (path);

	if (!value)
		value = "";

	len = strlen(value);

	for (i = 0; i < blacklist_len; i++) {
		const char *p = rindex(path, '/');
		if (p)
			p++;
		else
			p = path;
nih_info("comparing %s to %s", p, set_value_blacklist[i]);
		if (strcmp(p, set_value_blacklist[i]) == 0) {
			nih_error("attempted write to %s", set_value_blacklist[i]);
			return false;
		}
	}
	if ((f = fopen(path, "w")) == NULL) {
		nih_error("Error opening %s for writing", path);
		return false;
	}
	if (fprintf(f, "%s", value) < 0) {
		nih_error("Error writing %s to %s: %s", value, path,
			  strerror(errno));
		fclose(f);
		return false;
	}
	if (*value && value[len-1] != '\n')
		fprintf(f, "\n");
	if (fclose(f) != 0) {
		nih_error("Error closing %s", path);
		return false;
	}
	return true;
}

/*
 * Tiny helper to read the /proc/pid/ns/pid link for a given pid.
 * @pid: the pid whose link name to look up
 */
unsigned long read_pid_ns_link(int pid)
{
	int ret;
	struct stat sb;
	char path[100];
	ret = snprintf(path, 100, "/proc/%d/ns/pid", pid);
	if (ret < 0 || ret >= 100)
		return false;
	ret = stat(path, &sb);
	return sb.st_ino;
	return true;
}

/*
 * Tiny helper to read the /proc/pid/ns/user link for a given pid.
 * @pid: the pid whose link name to look up
 */
unsigned long read_user_ns_link(int pid)
{
	int ret;
	struct stat sb;
	char path[100];
	ret = snprintf(path, 100, "/proc/%d/ns/user", pid);
	if (ret < 0 || ret >= 100)
		return false;
	ret = stat(path, &sb);
	return sb.st_ino;
	return true;
}

bool realpath_escapes(char *path, char *safety)
{
		/* Make sure r doesn't try to escape his cgroup with .. */
	char *tmppath;
	if (!(tmppath = realpath(path, NULL))) {
		nih_error("Invalid path %s", path);
		return true;
	}
	if (strncmp(safety, tmppath, strlen(safety)) != 0) {
		nih_error("Improper requested path %s escapes safety %s",
			   path, safety);
		free(tmppath);
		return true;
	}
	free(tmppath);
	return false;
}

bool file_exists(const char *path)
{
	struct stat sb;
	if (stat(path, &sb) < 0)
		return false;
	return true;
}

bool dir_exists(const char *path)
{
	struct stat sb;
	if (stat(path, &sb) < 0 || !S_ISDIR(sb.st_mode))
		return false;
	return true;
}
