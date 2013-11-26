/* cgmanager
 *
 * Copyright © 2013 Stéphane Graber
 * Author: Stéphane Graber <stgraber@ubuntu.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

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

#include <sys/socket.h>

#include "org.linuxcontainers.cgmanager.h"

#define PACKAGE_NAME "cgmanager"
#define PACKAGE_VERSION "0.0"
#define PACKAGE_BUGREPORT ""

struct controller_mounts {
	char *controller;
	char *options;
	char *path;
};

static struct controller_mounts *all_mounts;
static int num_controllers;

/**
 * daemonise:
 *
 * Set to TRUE if we should become a daemon, rather than just running
 * in the foreground.
 **/
static int daemonise = FALSE;


int cgmanager_get_value (void *data, NihDBusMessage *message,
				 const char *controller, const char *cgroup,
		                 const char *key, char **value)

{
#if 1
	nih_info("get_value called, controller %s cgroup %s key %s",
		controller, cgroup, key);
	*value = "hi there";
	return 0;
#else
	int fd = 0;
	nih_assert (message != NULL);
	struct ucred ucred;
	socklen_t len;
	const char *key_path;
	char cgpath[MAXPATHLEN],
	     fullpath[MAXPATHLEN];

	if (!dbus_connection_get_socket(message->connection, &fd)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
		                             "Could  not get client socket.");
		return -1;
	}

	len = sizeof(struct ucred);
	NIH_MUST (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &ucred, &len) != -1);

	nih_info (_("Client fd is: %d (pid=%d, uid=%d, gid=%d)"),
		  fd, ucred.pid, ucred.uid, ucred.gid);

	/* get client's cgroup */
	if (get_pid_cgroup(pid, controller, cgpath) < 0) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
		                             "Could  not get client cgroup.");
		return -1;
	}


	if ((key_path = get_key_path(controller, key)) == NULL) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
		                             "invalid key %s for controller %s",
					     key, controller);
		return -1;
	}

	/* append the requested cgroup */
	ret = snprintf(fullpath, MAXPATHLEN, "%s/%s/%s", cgpath, cgroup, key_path);
	if (ret < 0 || ret >= MAXPATHLEN) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
		                             "path name too long for %s and %s, pid %d",
					     cgpath, cgroup, (int)pid);
		return -1;
	}

	/* Make sure client isn't passing us a bunch of bogus '../'s to
	 * try to read host files */
	if (!is_cgroup_path(controller, fullpath)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
		                             "invalid cgroup path '%s'", cgroup);
		return -1;
	}

	/* read and return the value */
	*value = read_string(cgpath);

	return 0;
#endif
}



static int
client_connect (DBusServer *server, DBusConnection *conn)
{
	nih_assert (server != NULL);
	nih_assert (conn != NULL);

	nih_info (_("Connection from private client"));

	NIH_MUST (nih_dbus_object_new (NULL, conn,
	          "/org/linuxcontainers/cgmanager",
	          cgmanager_interfaces, NULL));

	return TRUE;
}

static void
client_disconnect (DBusConnection *conn)
{
	nih_assert (conn != NULL);

	nih_info (_("Disconnected from private client"));
}


/**
 * options:
 *
 * Command-line options accepted by this program.
 **/
static NihOption options[] = {
	{ 0, "daemon", N_("Detach and run in the background"),
	  NULL, NULL, &daemonise, NULL },

	NIH_OPTION_LAST
};

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
static int setup_cgroup_mounts(void)
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

int
main (int   argc,
      char *argv[])
{
	char **             args;
	int                 ret;
	char *              pidfile_path = NULL;
	char *              pidfile = NULL;
	DBusServer *        server;


	nih_main_init (argv[0]);

	nih_option_set_synopsis (_("Control group manager"));
	nih_option_set_help (_("The cgroup manager daemon"));

	args = nih_option_parser (NULL, argc, argv, options, FALSE);
	if (! args)
		exit (1);

	/* Setup the DBus server */
	server = nih_dbus_server ("unix:path=/tmp/cgmanager", client_connect,
	                          client_disconnect);
	nih_assert (server != NULL);

	if (setup_cgroup_mounts() < 0) {
		nih_fatal ("Failed to set up cgroup mounts");
		exit(1);
	}

	/* Become daemon */
	if (daemonise) {
		if (nih_main_daemonise () < 0) {
			NihError *err;

			err = nih_error_get ();
			nih_fatal ("%s: %s", _("Unable to become daemon"),
				   err->message);
			nih_free (err);

			exit (1);
		}
	}

	ret = nih_main_loop ();

	/* Destroy any PID file we may have created */
	if (daemonise) {
		nih_main_unlink_pidfile();
	}

	return ret;
}
