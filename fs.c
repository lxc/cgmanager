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
#include <nih/hash.h>

#include <nih-dbus/dbus_connection.h>
#include <nih-dbus/dbus_proxy.h>

/* defines relating to the release agent */
#define AGENT SBINDIR "/cgm-release-agent"
#define AGENT_LINK_PATH "/run/cgmanager/agents"

char *all_controllers;

struct controller_mounts {
	char *controller;
	char *options;
	char *path;
	char *src;
	char *agent;
	struct controller_mounts *comounted;
	bool premounted;
	bool visited;
};

static struct controller_mounts *all_mounts;
static int num_controllers;

/*
 * the controller_mnts is an array of the mounts to export as the controller
 * list.  If freezer and devices are comounted, then they will form one
 * entry "freezer,devices"
 */
static int num_controller_mnts;
static char **controller_mnts;

static char *base_path;

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

/*
 * Where do we want to mount the controllers?  We used to mount
 * them under a tmpfs under /sys/fs/cgroup, for all to share.  Now
 * we want to have our socket there.  So how about /run/cgmanager/fs?
 * TODO read this from configuration file too
 * TODO do we want to create these in a tmpfs?
 */
bool setup_base_run_path(void)
{
	base_path = strdup("/run/cgmanager/fs");
	if (!base_path) {
		nih_fatal("%s: out of memory opening base path", __func__);
		return false;
	}
	if (mkdir("/run", 0755) < 0 && errno != EEXIST) {
		nih_fatal("%s: failed to create /run", __func__);
		return false;
	}
	if (mkdir("/run/cgmanager", 0755) < 0 && errno != EEXIST) {
		nih_fatal("%s: failed to create /run/cgmanager", __func__);
		return false;
	}
	if (mkdir("/run/cgmanager/fs", 0755) < 0 && errno != EEXIST) {
		nih_fatal("%s: failed to create /run/cgmanager/fs", __func__);
		return false;
	}
	if (mkdir(AGENT_LINK_PATH, 0755) < 0 && errno != EEXIST) {
		nih_fatal("%s: failed to create %s", __func__, AGENT_LINK_PATH);
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
	if (ret < 0 || ret >= MAXPATHLEN) {
		nih_fatal("%s: Error writing clone_children path", __func__);
		return;
	}
	f = fopen(p, "w");
	if (!f) {
		nih_fatal("%s: Failed to set clone_children", __func__);
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
	if (ret < 0 || ret >= MAXPATHLEN) {
		nih_fatal("%s: Error writing use_hierarchy path", __func__);
		return;
	}
	f = fopen(p, "w");
	if (!f) {
		nih_fatal("%s: Failed to set memory.use_hierarchy", __func__);
		return;
	}
	fprintf(f, "1\n");
	fclose(f);
}

static void zero_out(struct controller_mounts *c)
{
	memset(c, 0, sizeof(*c));
}

/*
 * Look for a controller_mounts struct for controller @c.
 * If found, set @found to true and return its index in all_mounts.
 * If not found, set @found to false and return index of the first
 * location in all_mounts whose controller is > @c, i.e. where it
 * should be inserted.
 */
static int find_controller_in_mounts(const char *c, bool *found)
{
	int cmp, low = 0, mid = low, high = num_controllers-1;

	*found = false;
	if (!num_controllers)
		return 0;

	while (low <= high) {
		if (high == low)
			break;
		if (high == low+1) {
			cmp = strcmp(c, all_mounts[low].controller);
			if (cmp <= 0) {
				mid = low;
				break;
			}
			cmp = strcmp(c, all_mounts[high].controller);
			if (cmp > 0) {
				mid = high + 1;
				if (mid >= num_controllers)
					mid = num_controllers-1;
				break;
			}
			mid = high;
			break;
		}
		mid = low + (high-low)/2;
		cmp = strcmp(c, all_mounts[mid].controller);
		if (cmp == 0)
			break;
		if (cmp < 0)
			high = mid;
		else
			low = mid;
	}

	cmp = strcmp(c, all_mounts[mid].controller);

	if (cmp == 0)
		*found = true;
	if (cmp > 0)
		mid++;

	return mid;
}

static bool fill_in_controller(struct controller_mounts *m, char *controller,
			char *src)
{
	int ret;
	char dest[MAXPATHLEN];

	ret = snprintf(dest, MAXPATHLEN, "%s/%s", base_path, src);
	if (ret < 0 || ret >= MAXPATHLEN) {
		nih_fatal("Error calculating pathname for %s and %s", base_path, src);
		return false;
	}
	m->controller = strdup(controller);
	if (!m->controller) {
		nih_fatal("Out of memory mounting controllers");
		return false;
	}
	m->options = NULL;
	m->path = strdup(dest);
	m->src = strdup(src);
	if (!m->path ||
			!m->src) {
		nih_fatal("Out of memory mounting controllers");
		return false;
	}
	nih_info(_("Arranged to mount %s onto %s"), m->controller, m->path);
	return true;
}

static bool save_mount_subsys(char *s)
{
	struct controller_mounts *tmp;
	char *src, *controller;
	int i, insert_pt, ret;
	size_t len = strlen(s);
	bool found;

	if (len > MAXPATHLEN) {
		nih_fatal("bad controller type: %s", s);
		return false;
	}
	if ((controller = strchr(s, '='))) {
		/* this is something like 'name=systemd' */
		src = alloca(len+7);
		/* so for controller we want 'systemd' */
		controller++;
		/* and for source we want "none,name=systemd" */
		ret = snprintf(src, len+6, "none,%s", s);
		if (ret < 0 || ret >= len+6) {
			nih_fatal("saving mount subsys for %s", s);
			ret = -1;
			goto out;
		}
	} else {
		controller = s;
		src = s;
	}

	insert_pt = find_controller_in_mounts(controller, &found);
	if (found)
		return true;

	tmp = realloc(all_mounts, (num_controllers+1) * sizeof(*all_mounts));
	if (!tmp) {
		nih_fatal("Out of memory mounting controllers");
		goto out;
	}
	all_mounts = tmp;

	for (i = num_controllers; i > insert_pt; i--)
		all_mounts[i] = all_mounts[i-1];
	zero_out(&all_mounts[insert_pt]);

	if (!fill_in_controller(&all_mounts[insert_pt], controller, src)) {
		ret = -1;
		goto out;
	}
	num_controllers++;
	return true;

out:
	return false;
}

static bool set_release_agent(struct controller_mounts *m)
{
	FILE *f;
	char path[MAXPATHLEN];
	int ret;

	if (m->premounted) {
		nih_info("%s was pre-mounted, not setting a release agent",
			m->controller);
		return true;
	}
	ret = snprintf(path, MAXPATHLEN, "%s/release_agent", m->path);
	if (ret < 0 || ret >= MAXPATHLEN) {
		nih_error("out of memory");
		return false;
	}
	if ((f = fopen(path, "w")) == NULL) {
		nih_error("failed to open %s for writing", path);
		return false;
	}
	if (fprintf(f, "%s\n", m->agent) < 0) {
		nih_error("failed to set release agent for %s",
				m->controller);
		fclose(f);
		return false;
	}
	if (fclose(f) != 0) {
		nih_error("failed to set release agent for %s",
				m->controller);
		return false;
	}
	return true;
}

static bool do_mount_subsys(int i)
{
	char *src, *dest, *controller;
	struct controller_mounts *m = &all_mounts[i];
	int ret;

	dest = m->path;
	controller = m->controller;
	src = m->src;

	if (mkdir(dest, 0755) < 0 && errno != EEXIST) {
		nih_fatal("Failed to create %s: %s", dest, strerror(errno));
		return false;
	}
	if (m->premounted)
		ret = mount(src, dest, "cgroup", 0, m->options);
	else
		ret = mount(src, dest, "cgroup", 0, src);
	if (ret < 0) {
		if (!m->premounted) {
			nih_debug("Failed mounting %s onto %s: %s", src, dest, strerror(errno));
			free(m->path);
			m->path = NULL;
			return true;
		}
		nih_fatal("Failed mounting %s onto %s: %s", src, dest, strerror(errno));
		if (m->premounted)
			nih_fatal("options was %s\n", m->options);
		return false;
	}
	nih_info(_("Mounted %s onto %s"), controller, dest);

	if (strcmp(controller, "cpuset") == 0) {
		set_clone_children(dest); // TODO make this optional?
		nih_info(_("set clone_children"));
	} else if (strcmp(controller, "memory") == 0) {
		set_use_hierarchy(dest);  // TODO make this optional?
		nih_info(_("set memory.use_hierarchy"));
	}

	if (!set_release_agent(m)) {
		nih_error("failed to set release agent for %s",
				m->controller);
		return false;
	}
	return true;
}

const char *controllers[] = { "blkio", "cpuset", "cpu", "cpuacct", "debug",
			"devices", "freezer", "memory", "net_cls", "net_prio",
			NULL };

static bool is_kernel_controller(const char *c)
{
	int i = 0;

	while (controllers[i]) {
		if (strcmp(controllers[i++], c) == 0)
			return true;
	}
	return false;
}

static bool process_mounted_subsystem(char *options)
{
	char *tok;
	nih_local char *cp_opts = NULL, *cp_opts_split = NULL;
	int i;
	bool found;

	tok = strtok(options, ",");
	while (tok) {
		if (strncmp(tok, "name=", 5) == 0) {
			i = find_controller_in_mounts(tok+5, &found);
			if (found) // jinkeys, multiple mounts already
				goto next;
			if (!save_mount_subsys(tok))
				return false;
			i = find_controller_in_mounts(tok+5, &found);
			if (!found)
				return false;
			all_mounts[i].premounted = true;
			if (!cp_opts)
				cp_opts = NIH_MUST( nih_strdup(NULL, tok) );
			else
				NIH_MUST( nih_strcat_sprintf(&cp_opts, NULL, ",%s", tok) );
		} else if (is_kernel_controller(tok)) {
			i = find_controller_in_mounts(tok, &found);
			if (found) // jinkeys, multiple mounts already
				goto next;
			if (!save_mount_subsys(tok))
				return false;
			i = find_controller_in_mounts(tok, &found);
			if (!found)
				return false;
			all_mounts[i].premounted = true;
			if (!cp_opts)
				cp_opts = NIH_MUST( nih_strdup(NULL, tok) );
			else
				NIH_MUST( nih_strcat_sprintf(&cp_opts, NULL, ",%s", tok) );
		}
next:
		tok = strtok(NULL, ",");
	}

	if (!cp_opts)
		return true;

	cp_opts_split = NIH_MUST( nih_strdup(NULL, cp_opts) );
	tok = strtok(cp_opts_split, ",");
	while (tok) {
		if (strncmp(tok, "name=", 5) == 0)
			i = find_controller_in_mounts(tok+5, &found);
		else
			i = find_controller_in_mounts(tok, &found);
		if (!found)
			return false;
		all_mounts[i].options = strdup(cp_opts);
		if (!all_mounts[i].options)
			return false;
		tok = strtok(NULL, ",");
	}

	return true;
}

/*
 * parse /proc/self/mounts looking for already-mounted subsystems
 */
static bool collect_premounted_subsystems(void)
{
	char line[1024], *p1, *p2, *p3, *p4;

	FILE *f = fopen("/proc/self/mounts", "r");
	if (!f)
		return false;
	while (fgets(line, 1024, f)) {
		p1 = strchr(line, ' ');
		if (!p1)
			goto bad;
		*p1 = '\0';
		p2 = strchr(++p1, ' ');
		if (!p2)
			goto bad;
		*p2 = '\0';
		p2++;
		p3 = strchr(p2, ' ');
		if (!p3)
			goto bad;
		*p3 = '\0';
		if (strcmp(p2, "cgroup") != 0)
			continue;
		p4 = strchr(++p3, ' ');
		if (!p4)
			goto bad;
		*p4 = '\0';
		if (!process_mounted_subsystem(p3))
			goto bad;
	}
	fclose(f);
	return true;
bad:
	fclose(f);
	return false;
}

static bool collate_premounted_subsystems(void)
{
	int i;

	for (i = 0;  i < num_controllers; i++) {
		nih_local char *opts = NULL;
		char *tok;
		struct controller_mounts *first = NULL, *last = NULL;
		int j;
		bool found;

		first = &all_mounts[i];
		if (!first->premounted)
			continue;
		if (first->comounted) // already linked
			continue;
		if (!first->options)
			continue;
		opts = NIH_MUST( nih_strdup(NULL, first->options) );
		tok = strtok(opts, ",");
		while (tok) {
			if (strncmp(tok, "name=", 5) == 0)
				j = find_controller_in_mounts(tok+5, &found);
			else
				j = find_controller_in_mounts(tok, &found);
			if (!found)
				return false;
			if (!last) {
				last = &all_mounts[j];
				first->comounted = last;
			} else {
				last->comounted = &all_mounts[j];
				last = last->comounted;
			}
			tok = strtok(NULL, ",");
		}
	}

	return true;
}

static bool collect_kernel_subsystems(void)
{
	FILE *cgf;
	char line[400];
	bool bret = false;

	if ((cgf = fopen("/proc/cgroups", "r")) == NULL) {
		nih_fatal ("Error opening /proc/cgroups: %s", strerror(errno));
		return false;
	}
	while (fgets(line, 400, cgf)) {
		char *p;

		if (line[0] == '#')
			continue;
		p = strchr(line, '\t');
		if (!p)
			continue;
		*p = '\0';

		if (!save_mount_subsys(line)) {
			nih_fatal("Error storing subsystem %s", line);
			goto out;
		}
	}
	bret = true;

out:
	fclose(cgf);
	return bret;
}

static void prune_from_string(char *list, char *c)
{
	char *f;
	size_t len;
	char *origlist = list;

	if (strncmp(c, "none,", 5) == 0)
		c += 5;
	len = strlen(c);
again:
	if (!list)
		return;
	f = strstr(list, c);
	if (!f)
		return;
	if (f > origlist && *(f-1) != ',') {
		list = f+len;
		goto again;
	}
	if (*(f+len) != ',' && *(f+len) != '\0') {
		list = f+len;
		goto again;
	}
	/* now we know for sure that [f-1,f+len+1] == ",f," */
	if (f[len])
		memmove(f, f+len+1, strlen(f+len+1)+1);
	else
		*(f-1) = '\0';
	goto again;
}

char *skip_nameeq(char *controller)
{
	if (strncmp(controller, "name=", 5) == 0)
		return controller+5;
	return controller;
}

/*
 * Build the list of controllers which we return as the result of
 * ListControllers
 */
static void build_controller_mntlist(void)
{
	int i;
	struct controller_mounts *m, *m2;
	num_controller_mnts = 0;

	for (i = 0; i < num_controllers; i++) {
		char *srclist;
		m = &all_mounts[i];
		if (m->visited)
			continue;
		controller_mnts = realloc(controller_mnts,
				(num_controller_mnts+1)*(sizeof(char *)));
		if (!controller_mnts) {
			nih_fatal("Out of memory building mntlist");
			exit(1);
		}
		srclist = NIH_MUST( nih_strdup(NULL, skip_nameeq(m->controller)) );
		m->visited = true;
		m2 = m->comounted;
		while (m2) {
			/*
			 * XXX Should we use m2->controller or m2->options here?
			 * options would include "none,".  does controller include
			 * the 'name=' part of systemd?  If not do we need ot add it
			 * by hande?
			 */
			NIH_MUST( nih_strcat_sprintf(&srclist, NULL, ",%s",
						skip_nameeq(m2->controller)) );
			m2->visited = true;
			m2 = m2->comounted;
		}
		controller_mnts[num_controller_mnts] = srclist;
		num_controller_mnts++;
	}
}

static void print_debug_controller_info(void)
{
	int i;
	struct controller_mounts *m;

	nih_debug("all unique controllers: %s", all_controllers);

	for (i = 0; i < num_controllers; i++) {
		m = &all_mounts[i];
		nih_debug("%d: controller %s", i, m->controller);
		nih_debug("    src %s path %s options %s",
			m->src, m->path ? m->path : "(none)", m->options ? m->options : "(none)");
		nih_debug("    agent: %s", m->agent ? m->agent : "(none)");
		nih_debug("    premounted: %s comounted: %s",
			m->premounted ? "yes" : "no",
			m->comounted ? m->comounted->controller : "(none)");
	}
}

void do_list_controllers(void *parent, char ***output)
{
	int i;

	nih_assert(output);
	*output = NIH_MUST( nih_alloc(parent, (num_controller_mnts+1) * sizeof(char *)) );
	(*output)[num_controller_mnts] = NULL;
	
	/* XXX
	 * This will actually not be right.
	 * if we have freezer,devices co-mounted, we'll have two separate
	 * entries for the two.
	 * So TODO - figure out what we want in that case, and provide it
	 */
	for (i = 0; i < num_controller_mnts; i++)
		(*output)[i] = NIH_MUST( nih_strdup(parent, controller_mnts[i]) );
}

void do_prune_comounts(char *controllers)
{
	char *p1 = controllers, *p2;
	int i;
	bool found;
	struct controller_mounts *m1;

	while (p1) {
		p2 = strchr(p1, ',');
		if (!p2)
			return;
		*p2 = '\0';
		i = find_controller_in_mounts(p1, &found);
		if (!found) {
			*p2 = ',';
			p1 = p2+1;
			continue;
		}
		m1 = all_mounts[i].comounted;
		while (m1 && m1 != &all_mounts[i]) {
			prune_from_string(p2+1, m1->src);
			m1 = m1->comounted;
		}
		*p2 = ',';
		p1 = p2+1;
	}
}

static void build_all_controllers(void)
{
	int i;
	char *c;

	for (i = 0;  i < num_controllers;  i++) {
		c = all_mounts[i].src;
		if (strncmp(c, "none,", 5) == 0)
			c += 5;
		if (!all_controllers)
			all_controllers = NIH_MUST( nih_strdup(NULL, c) );
		else
			NIH_MUST( nih_strcat_sprintf(&all_controllers, NULL, ",%s", c) );
	}

	do_prune_comounts(all_controllers);
}

int collect_subsystems(char *extra_mounts)
{
	/* first collect all already-mounted subsystems */
	if (!collect_premounted_subsystems())
		return -1;

	/* handle the requested extra-mounts, which are not in /proc/cgroups */
	if (extra_mounts) {
		char *e;
		for (e = strtok(extra_mounts, ","); e; e = strtok(NULL, ",")) {
			if (!save_mount_subsys(e)) {
				nih_fatal("Error loading subsystem \"%s\"", e);
				return -1;
			}
		}
	}

	if (!collect_kernel_subsystems())
		return -1;

	if (!collate_premounted_subsystems())
		return -1;

	build_all_controllers();

	build_controller_mntlist();
	print_debug_controller_info();

	return 0;
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
	int i;

	if (unshare(CLONE_NEWNS) < 0) {
		nih_fatal("Failed to unshare a private mount ns: %s", strerror(errno));
		return 0;
	}

	if (mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, 0) < 0)
		nih_warn("Failed to re-mount / non-shared");

	for (i=0; i<num_controllers; i++) {
		if (!do_mount_subsys(i)) {
			nih_fatal("Failed mounting cgroups");
			return -1;
		}
	}

	return 0;
}

/*
 * In the old release agent support, the release agent is not told the
 * controller in which the cgroup was freed.  Therefore we need to have a
 * different binary for each mounted controller.  We will create these under
 * /run/cgmanager/agents/ as symlinks to /sbin/cgm-release-agent, i.e.
 * /run/cgmanager/agents/cgm-release-agent.freezer.
 */
bool create_agent_symlinks(void)
{
	struct stat statbuf;
	char buf[MAXPATHLEN];
	int i, ret, plen;

	ret = stat(AGENT, &statbuf);
	if (ret < 0) {
		nih_error("release agent not found");
		return false;
	}

	plen = snprintf(buf, MAXPATHLEN, "%s/", AGENT_LINK_PATH);
	if (plen < 0 || plen >= MAXPATHLEN) {
		nih_error("memory error");
		return false;
	}

	for (i=0; i<num_controllers; i++) {
		if (all_mounts[i].premounted)
			continue;

		ret = snprintf(buf+plen, MAXPATHLEN-plen, "cgm-release-agent.%s",
				all_mounts[i].controller);
		if (ret < 0 || ret >= MAXPATHLEN) {
			nih_error("path names too long");
			return false;
		}
		nih_info("buf is %s", buf);
		if (!file_exists(buf)) {
			if (symlink(AGENT, buf) < 0) {
				nih_error("failed to create release agent for %s",
					all_mounts[i].controller);
				return false;
			}
		}
		if ((all_mounts[i].agent = strdup(buf)) == NULL) {
			nih_error("out of memory");
			return false;
		}
	}

	return true;
}

static inline void drop_newlines(char *s)
{
	int l;

	for (l=strlen(s); l>0 && s[l-1] == '\n'; l--)
		s[l-1] = '\0';
}

/*
 * The user will pass in 'cpuset' or 'systemd'.  /proc/self/cgroup will
 * show 'cpuset:' or 'name=systemd:'.  We have to account for that.
 */
static bool is_same_controller(const char *cmp, const char *cnt)
{
	if (strcmp(cmp, cnt) == 0)
		return true;
	if (strncmp(cmp, "name=", 5) != 0)
		return false;
	if (strcmp(cmp+5, cnt) == 0)
		return true;
	return false;
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

	sprintf(path, "/proc/%d/cgroup", pid);
	if ((f = fopen(path, "r")) == NULL) {
		nih_error("could not open cgroup file for %d", pid);
		return NULL;
	}
	while (getline(&line, &len, f) != -1) {
		char *c1, *c2;
		char *token, *saveptr = NULL;
		if ((c1 = strchr(line, ':')) == NULL)
			continue;
		if ((c2 = strchr(++c1, ':')) == NULL)
			continue;
		*c2 = '\0';
		for (; (token = strtok_r(c1, ",", &saveptr)); c1 = NULL) {
			if (!is_same_controller(token, controller))
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
bool hostuid_to_ns(uid_t uid, pid_t pid, uid_t *answer)
{
	FILE *f;
	uid_t nsuid, hostuid;
	unsigned int count;
	char line[400];
	int ret;

	sprintf(line, "/proc/%d/uid_map", pid);
	if ((f = fopen(line, "r")) == NULL) {
		return false;
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
			*answer = (uid - hostuid) + nsuid;
			return true;
		}
	}
	fclose(f);
	return false;
}

/*
 * pid may access path if the uids are the same, or if
 * path's uid is mapped into the userns and pid is root
 * there, or if the gids are the same and path has mode
 * in group rights, or if path has mode in other rights.
 *
 * uid and gid are passed in to avoid recomputation.  uid
 * and gid are the host uids, not mapped into the ns.
 *
 * TODO should we use acls
 * TODO should we be checking for x access over each directory along the path
 */
bool may_access(pid_t pid, uid_t uid, gid_t gid, const char *path, int mode)
{
	struct stat sb;
	int ret;
	uid_t nsruid, nsvuid;

	ret = stat(path, &sb);
	if (ret < 0) {
		nih_error("Could not look up %s\n", path);
		return false;
	}

	// TODO should we check capabilities in case of (host) root?
	if (uid == 0)
		return true;

	/*
	 * If victim is mapped into requestor's uid namespace, and
	 * requestor is root there, then that suffices.
	 */
	if (hostuid_to_ns(sb.st_uid, pid, &nsvuid) &&
			hostuid_to_ns(uid, pid, &nsruid) && nsruid == 0)
		return true;

	if (uid == sb.st_uid) {
		if (mode == O_RDONLY && sb.st_mode & S_IRUSR)
			return true;
		if (mode == O_RDWR && ((sb.st_mode & (S_IRUSR|S_IWUSR)) == (S_IRUSR|S_IWUSR)))
			return true;
		if (mode == O_WRONLY && sb.st_mode & S_IWUSR)
			return true;
		return false;
	}
	if (gid == sb.st_gid) {
		if (mode == O_RDONLY && sb.st_mode & S_IRGRP)
			return true;
		if (mode == O_RDWR && ((sb.st_mode & (S_IRGRP|S_IWGRP)) == (S_IRGRP|S_IWGRP)))
			return true;
		if (mode == O_WRONLY && sb.st_mode & S_IWGRP)
			return true;
		return false;
	}

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
	bool found;

	i = find_controller_in_mounts(controller, &found);
	if (!found) {
		if (strncmp(controller, "name=", 5) == 0) {
			i = find_controller_in_mounts(controller+5, &found);
			if (found)
				return all_mounts[i].path;
		}
		return NULL;
	}
	return all_mounts[i].path;
}

int get_path_depth(const char *p)
{
	int depth = 0;

	if (!p)
		return 0;
	while (*p) {
		while (*p && *p == '/')
			p++;
		if (*p)
			depth++;
		while (*p && *p != '/')
			p++;
	}
	return depth;
}

/*
 * Calculate a full path to the cgroup being requested.
 * @pid is the process making the request
 * @controller is the mounted controller under which we will look.
 * @cgroup is the cgroup which @pid is asking about.  If @cgroup is
 * @path is the path in which to return the full cgroup path.
 *    "a/b", then we concatenate "/cgroup/for/pid" with "a/b"
 *    If @cgroup is "/a/b", then we use "/a/b"
 * @depth, if not null, will contain the depth of the tasks's
 * current cgroup plus the proposed new cgroup.
 */
bool compute_pid_cgroup(pid_t pid, const char *controller, const char *cgroup,
		char *path, int *depth)
{
	int ret;
	char requestor_cgpath[MAXPATHLEN], fullpath[MAXPATHLEN];
	/*
	 * cg contains the the requestor's current cgroup, to prepend to
	 * the requested cgroup - or "" if requesting an absolute path
	 */
	char *cg = "";
	const char *cont_path;
	bool abspath = false;

	if (!cgroup) {
		nih_error("%s: BUG: called with NULL cgroup\n", __func__);
		return false;
	}

	if (cgroup[0] != '/') {
		cg = pid_cgroup(pid, controller, requestor_cgpath);
		if (!cg) {
			nih_error("Found no cgroup entry for pid %lu controller %s\n",
				(unsigned long)pid, controller);
			return false;
		}
	} else
		abspath = true;

	if (depth)
		*depth = get_path_depth(cg) + get_path_depth(cgroup);

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
		nih_error("Invalid path %s (%s)", fullpath, strerror(errno));
		return false;
	}
	if (strncmp(path, cont_path, strlen(cont_path)) != 0) {
		nih_error("invalid cgroup path '%s' for pid %d", cgroup, pid);
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
 * Note: this is not a general purpose I/O function.  It is specifically
 * written for virtual filesystems (cgroupfs) where we do know that the
 * file ends in \0, and do not know that stat.st_size is reliable.
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
	int nrpids = 0, alloced_pids = 0, pid;
	FILE *fin = fopen(path, "r");

	*pids = NULL;
	if (!fin) {
		nih_error("Error opening %s: %s", path, strerror(errno));
		return -1;
	}

	while (fscanf(fin, "%d", &pid) == 1) {
		if (nrpids + 1 >= alloced_pids) {
			int32_t *tmp;
			alloced_pids += 256;
			tmp = nih_realloc(*pids, parent,
					  alloced_pids*sizeof(int32_t));
			if (!tmp) {
				if (*pids)
					nih_free(*pids);
				pids = NULL;
				nih_error("Out of memory getting pid list");
				goto out;
			}
			*pids = tmp;
		}
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
	uid_t u;
	gid_t g;
	FILE *f;

	*uid = -1;
	*gid = -1;
	sprintf(line, "/proc/%d/status", pid);
	if ((f = fopen(line, "r")) == NULL) {
		nih_error("Error opening %s: %s", line, strerror(errno));
		return;
	}
	while (fgets(line, 400, f)) {
		if (strncmp(line, "Uid:", 4) == 0) {
			if (sscanf(line+4, "%u", &u) != 1) {
				nih_error("bad uid line for pid %u", pid);
				fclose(f);
				return;
			}
			*uid = u;
		} else if (strncmp(line, "Gid:", 4) == 0) {
			if (sscanf(line+4, "%u", &g) != 1) {
				nih_error("bad gid line for pid %u", pid);
				fclose(f);
				return;
			}
			*gid = g;
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

	nih_assert (path);
	len = strlen(path);
	if (chown(path, uid, gid) < 0)
		return false;

	if (all_children) {
		// chown all the files in the directory
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
				nih_error("Failed to chown file %s to %u:%u",
					fpath, uid, gid);
		}
		closedir(d);
	} else {
		// chown only the tasks and procs files
		nih_local char *fpath = NULL;
		fpath = NIH_MUST( nih_sprintf(NULL, "%s/cgroup.procs", path) );
		if (chown(fpath, uid, gid) < 0)
			nih_error("Failed to chown procs file %s", fpath);
		sprintf(fpath+len, "/tasks");
		if (chown(fpath, uid, gid) < 0)
			nih_error("Failed to chown tasks file %s", fpath);
	}

out:
	return true;
}

/*
 * Given a directory path, chmod it.
 *
 * Caller has already checked for permission
 *
 * Return true so long as we could chown the directory itself.
 */
bool chmod_cgroup_path(const char *path, int mode)
{
	nih_assert (path);
	if (chmod(path, mode) < 0) {
		nih_error("Failed to chown tasks file %s", path);
		return false;
	}

	return true;
}

/*
 * TODO - make this more baroque to allow ranges etc
 */
static char *set_value_blacklist[] = { "tasks",
	"release-agent",
	"cgroup.procs",
	"notify-on-release"
};
static size_t blacklist_len = sizeof(set_value_blacklist)/sizeof(char *);

bool set_value_trusted(const char *path, const char *value)
{
	int len;
	FILE *f;

	nih_assert (path);

	if (!value)
		value = "";

	len = strlen(value);

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
bool set_value(const char *path, const char *value)
{
	int i;

	nih_assert (path);

	for (i = 0; i < blacklist_len; i++) {
		const char *p = strrchr(path, '/');
		if (p)
			p++;
		else
			p = path;
		if (strcmp(p, set_value_blacklist[i]) == 0) {
			nih_error("attempted write to %s", set_value_blacklist[i]);
			return false;
		}
	}

	return set_value_trusted(path, value);
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
	if (ret < 0 || ret >= 100) {
		nih_fatal("Error reading pid ns link");
		exit(1);
	}
	ret = stat(path, &sb);
	return sb.st_ino;
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
	if (ret < 0 || ret >= 100) {
		nih_fatal("Error reading user ns link");
		exit(1);
	}
	ret = stat(path, &sb);
	return sb.st_ino;
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

/*
 * move_self_to_root: called by cgmanager at startup to make sure
 * it starts in /
 */
bool move_self_to_root(void)
{
	char path[MAXPATHLEN];
	int i, ret;
	pid_t me = getpid();
	FILE *f;

	for (i = 0; i < num_controllers; i++) {
		if (!all_mounts[i].path)
			continue;
		ret = snprintf(path, MAXPATHLEN, "%s/tasks", all_mounts[i].path);
		if (ret < 0 || ret >= MAXPATHLEN)
			return false;
		if ((f = fopen(path, "w")) == NULL)
			return false;
		if (fprintf(f, "%d\n", me) <= 0) {
			fclose(f);
			return false;
		}
		if (fclose(f) != 0)
			return false;
	}
	return true;
}

/*
 * get_directory_children:
 *
 * @parent: parent which will be given a reference to the returned string
 * (to allow the returned value to be freed automatically when @parent is
 * freed).
 * @path: Full path whose child directories to list.
 * output: pointer to which the list of directory names will be stored.
 * @type: type of file (dir or regular file) to return
 *
 * Read all child directories under @path.
 *
 * Returns: Number of directories read.  The names will be placed in the
 * null-terminated array @output.
 */
int get_directory_children(void *parent, const char *path, char ***output, unsigned char type)
{
	int used = 0, alloced = 5;
	DIR *d;
	struct dirent dirent, *direntp;

	nih_assert(output);
	d = opendir(path);
	if (!d) {
		nih_error("%s: failed to open directory %s: %s",
			__func__, path, strerror(errno));
		return -1;
	}
	*output = NIH_MUST( nih_alloc(parent, alloced * sizeof(char *)) );
	(*output)[0] = NULL;
	while (readdir_r(d, &dirent, &direntp) == 0 && direntp) {
		if (!strcmp(direntp->d_name, ".") || !strcmp(direntp->d_name, ".."))
			continue;
		if (type != direntp->d_type)
			continue;
		if (used+1 >= alloced) {
			char **tmp;
			alloced += 5;
			tmp = nih_realloc(*output, parent, alloced * sizeof(char *));
			if (!tmp) {
				nih_free(*output);
				*output = NULL;
				nih_error("%s: Out of memory", __func__);
				closedir(d);
				return -1;
			}
			*output = tmp;
		}
		(*output)[used] = NIH_MUST( nih_strdup(parent, direntp->d_name) );
		(*output)[used+1] = NULL;
		used++;
	}
	closedir(d);
	return used;
}

int do_list_controller_keys(void *parent, const char *controller, char ***output)
{
	const char *path;

	if (!(path = get_controller_path(controller)))
		return -1;

	return get_directory_children(parent, path, output, DT_REG);
}

bool was_premounted(const char *controller)
{
	bool found;
	int i = find_controller_in_mounts(controller, &found);
	if (!found)
		return false;
	return all_mounts[i].premounted;
}
