#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sched.h>
#include <sys/types.h>
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
			nih_fatal("%s was already mounted", line);
			ret = -1;
			goto out;
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
		num_controllers++;
	}
	nih_info("mounted %d controllers", num_controllers);
	ret = 0;
out:
	fclose(cgf);
	return ret;
}
