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
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/param.h>
#include <stdbool.h>
#include <libgen.h>

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

#include "fs.h"

#include "org.linuxcontainers.cgmanager.h"

#define PACKAGE_NAME "cgmanager"
#define PACKAGE_VERSION "0.0"
#define PACKAGE_BUGREPORT ""

/**
 * daemonise:
 *
 * Set to TRUE if we should become a daemon, rather than just running
 * in the foreground.
 **/
static int daemonise = FALSE;

static pid_t get_scm_pid(int sock)
{
        struct msghdr msg = { 0 };
        struct iovec iov;
        struct cmsghdr *cmsg;
	struct ucred cred;
        char cmsgbuf[CMSG_SPACE(sizeof(cred))];
        char buf[1];
	int ret, optval = 1;

	if (setsockopt(sock, SOL_SOCKET, SO_PASSCRED, &optval,
			sizeof(optval)) == -1) {
		perror("setsockopt");
		return -1;
	}

	cred.pid = -1;
        msg.msg_name = NULL;
        msg.msg_namelen = 0;
        msg.msg_control = cmsgbuf;
        msg.msg_controllen = sizeof(cmsgbuf);

        iov.iov_base = buf;
        iov.iov_len = sizeof(buf);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

	ret = recvmsg(sock, &msg, 0);
	if (ret <= 0)
		goto out;

        cmsg = CMSG_FIRSTHDR(&msg);

        if (cmsg && cmsg->cmsg_len == CMSG_LEN(sizeof(struct ucred)) &&
            cmsg->cmsg_level == SOL_SOCKET &&
            cmsg->cmsg_type == SCM_CREDENTIALS) {
		memcpy(&cred, CMSG_DATA(cmsg), sizeof(cred));
        }
out:
        return cred.pid;
}

int cgmanager_move_pid (void *data, NihDBusMessage *message,
				 const char *controller, char *cgroup)
{
	int fd = 0, ret;
	struct ucred ucred;
	socklen_t len;
	pid_t target_pid;
	char rcgpath[MAXPATHLEN], path[MAXPATHLEN];
	FILE *f;

	if (message == NULL) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"message was null");
		return -1;
	}

nih_info("controller %s cgroup %s", controller, cgroup);
	if (!dbus_connection_get_socket(message->connection, &fd)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
		                             "Could  not get client socket.");
		return -1;
	}

	len = sizeof(struct ucred);
	NIH_MUST (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &ucred, &len) != -1);
	target_pid = get_scm_pid(fd);

nih_info("pid %d", (int)target_pid);

	// TODO verify that ucred.pid and target_pid either have the same
	// uid, or that ucred.pid is uid 0 in target_pid's namespace.
	// NOTE that right now, since scm_credentials require CAP_SYS_ADMIN,
	// this is a given.

	nih_info (_("Client fd is: %d (pid=%d, uid=%d, gid=%d)"),
		  fd, ucred.pid, ucred.uid, ucred.gid);

	if (cgroup[0] == '/' || cgroup[0] == '.') {
		// We could try to be accomodating, but let's not fool around right now
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Bad requested cgroup path: %s", cgroup);
		return -1;
	}

	// Get r's current cgroup in rcgpath
	if (!compute_pid_cgroup(ucred.pid, controller, "", rcgpath)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Could not determine the requested cgroup");
		return -1;
	}
	/* rcgpath + / + cgroup + /tasks + \0 */
	if (strlen(rcgpath) + strlen(cgroup) > MAXPATHLEN+8) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Path name too long");
		return -1;
	}
	strcpy(path, rcgpath);
	strncat(path, "/", MAXPATHLEN-1);
	strncat(path, cgroup, MAXPATHLEN-1);
	{
		/* Make sure r doesn't try to escape his cgroup with .. */
		char *tmppath;
		if (!(tmppath = realpath(path, NULL))) {
			nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
				"Invalid path %s", path);
			return -1;
		}
		if (strncmp(rcgpath, tmppath, strlen(rcgpath)) != 0) {
			nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
				"Invalid cgroup path %s requested by pid %d",
				  path, (int)ucred.pid);
			free(tmppath);
			return -1;
		}
		free(tmppath);
	}
	// is r allowed to descend under the parent dir?
	if (!may_access(ucred.pid, ucred.uid, ucred.gid, path, O_RDONLY)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"pid %d (uid %d gid %d) may not write under %s",
			(int)ucred.pid, (int)ucred.uid, (int)ucred.gid, path);
		return -1;
	}
	// is r allowed to write to tasks file?
	strncat(path, "/tasks", MAXPATHLEN-1);
	if (!may_access(ucred.pid, ucred.uid, ucred.gid, path, O_WRONLY)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"pid %d (uid %d gid %d) may not write under %s",
			(int)ucred.pid, (int)ucred.uid, (int)ucred.gid, path);
		return -1;
	}
	f = fopen(path, "w");
	if (!f) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed to open %s", path);
		return -1;
	}
	if (fprintf(f, "%d", target_pid) < 0) {
		fclose(f);
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed to open %s", path);
		return -1;
	}
	if (fclose(f) != 0) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed to write %d to %s", (int)target_pid, path);
		return -1;
	}
	nih_info("%d moved to %s:%s by %d's request", (int)target_pid,
		controller, cgroup, (int)ucred.pid);
	return 0;
}

int cgmanager_create (void *data, NihDBusMessage *message,
				 const char *controller, char *cgroup)
{
	int fd = 0, ret;
	struct ucred ucred;
	socklen_t len;
	char rcgpath[MAXPATHLEN], path[MAXPATHLEN], *copy, *fnam, *dnam;

	if (message == NULL) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"message was null");
		return -1;
	}

	if (!dbus_connection_get_socket(message->connection, &fd)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
		                             "Could  not get client socket.");
		return -1;
	}

	len = sizeof(struct ucred);
	NIH_MUST (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &ucred, &len) != -1);

	nih_info (_("Client fd is: %d (pid=%d, uid=%d, gid=%d)"),
		  fd, ucred.pid, ucred.uid, ucred.gid);

	if (!cgroup || cgroup == "")  // nothing to do
		return 0;
	if (cgroup[0] == '/' || cgroup[0] == '.') {
		// We could try to be accomodating, but let's not fool around right now
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Bad requested cgroup path: %s", cgroup);
		return -1;
	}

	// TODO - support comma-separated list of controllers?  Not sure it's worth it

	// Get r's current cgroup in rcgpath
	if (!compute_pid_cgroup(ucred.pid, controller, "", rcgpath)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Could not determine the requested cgroup");
		return -1;
	}
	if (strlen(rcgpath) + strlen(cgroup) > MAXPATHLEN) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Path name too long");
		return -1;
	}
	copy = strdup(cgroup);
	if (!copy) {
		nih_dbus_error_raise_printf (DBUS_ERROR_NO_MEMORY,
			"Out of memory copying cgroup name");
		return -1;
	}
	fnam = basename(copy);
	dnam = dirname(copy);
	strcpy(path, rcgpath);
	if (strcmp(dnam, ".") != 0) {
		char *tmppath;
		// verify that the real path is below the controller path
		strncat(path, "/", MAXPATHLEN-1);
		strncat(path, dnam, MAXPATHLEN-1);
		if (!(tmppath = realpath(path, NULL))) {
			nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
				"Invalid path %s", path);
			free(copy);
			return -1;
		}
		if (strncmp(rcgpath, tmppath, strlen(rcgpath)) != 0) {
			nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
				"Invalid cgroup path %s requested by pid %d",
				  path, (int)ucred.pid);
			free(copy);
			free(tmppath);
			return -1;
		}
		free(tmppath);
	}

	// is r allowed to create under the parent dir?
	if (!may_access(ucred.pid, ucred.uid, ucred.gid, path, O_RDWR)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"pid %d (uid %d gid %d) may not create under %s",
			(int)ucred.pid, (int)ucred.uid, (int)ucred.gid, path);
		free(copy);
		return -1;
	}
	strncat(path, "/", MAXPATHLEN-1);
	strncat(path, fnam, MAXPATHLEN-1);
	ret = mkdir(path, 0755);
	if (ret < 0) {  // Should we ignore EEXIST?  Ok, but don't chown.
		free(copy);
		if (errno == EEXIST)
			return 0;
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"failed to create %s", path);
		return -1;
	}
	ret = chown(path, ucred.uid, ucred.gid);
	if (ret < 0) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed to change ownership on %s to %d:%d",
			path, (int)ucred.uid, (int)ucred.gid);
		rmdir(path);
		free(copy);
		return -1;
	}

	free(copy);
	nih_info("Created %s for %d (%d:%d)", path, (int)ucred.pid,
		 (int)ucred.uid, (int)ucred.gid);
	return 0;
}

int cgmanager_get_my_cgroup (void *data, NihDBusMessage *message,
				 const char *controller, char **value)
{
	int fd = 0;
	struct ucred ucred;
	socklen_t len;
	char path[MAXPATHLEN];

	if (message == NULL) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Message was NULL");
		return -1;
	}

	const char *controller_path = get_controller_path(controller);
	if (!controller_path) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Controller not mounted: %s", controller);
		return -1;
	}

	if (!dbus_connection_get_socket(message->connection, &fd)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
		                             "Could  not get client socket.");
		return -1;
	}

	len = sizeof(struct ucred);
	NIH_MUST (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &ucred, &len) != -1);

	nih_info (_("Client fd is: %d (pid=%d, uid=%d, gid=%d)"),
		  fd, ucred.pid, ucred.uid, ucred.gid);

	if (!compute_pid_cgroup(ucred.pid, controller, "", path)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Could not determine the requested cgroup");
		return -1;
	}

	int cplen = strlen(controller_path);
	if (strlen(path) < cplen) {
		nih_dbus_error_raise_printf (DBUS_ERROR_NO_MEMORY,
			"Out of memory copying controller path");
		return -1;
	}

	*value = strdup(path + cplen);

	return 0;
}

int cgmanager_get_value (void *data, NihDBusMessage *message,
				 const char *controller, const char *req_cgroup,
		                 const char *key, char **value)

{
	int fd = 0;
	struct ucred ucred;
	socklen_t len;
	char path[MAXPATHLEN], *fullpath;

	if (message == NULL) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Message was NULL");
		return -1;
	}

	if (!dbus_connection_get_socket(message->connection, &fd)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
		                             "Could  not get client socket.");
		return -1;
	}

	len = sizeof(struct ucred);
	NIH_MUST (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &ucred, &len) != -1);

	nih_info (_("Client fd is: %d (pid=%d, uid=%d, gid=%d)"),
		  fd, ucred.pid, ucred.uid, ucred.gid);

	if (!compute_pid_cgroup(ucred.pid, controller, req_cgroup, path)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Could not determine the requested cgroup");
		return -1;
	}

	/* Check access rights to the cgroup directory */
	if (!may_access(ucred.pid, ucred.uid, ucred.gid, path, O_RDONLY)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Pid %d may not access %s\n", (int)ucred.pid, path);
		return -1;
	}

	/* append the filename */
	if (strlen(path) + strlen(key) + 2 > MAXPATHLEN) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"filename too long for cgroup %s key %s", path, key);
		return -1;
	}

	strncat(path, "/", MAXPATHLEN-1);
	strncat(path, key, MAXPATHLEN-1);

	/* Check access rights to the file itself */
	if (!may_access(ucred.pid, ucred.uid, ucred.gid, path, O_RDONLY)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Pid %d may not access %s\n", (int)ucred.pid, path);
		return -1;
	}

	/* read and return the value */
	*value = file_read_string(path);
	if (!*value) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed to read value from %s", path);
		return -1;
	}

	nih_info("Sending to client: %s", *value);
	return 0;
}

static dbus_bool_t allow_user(DBusConnection *connection, unsigned long uid, void *data)
{
	return TRUE;
}

static int
client_connect (DBusServer *server, DBusConnection *conn)
{
	if (server == NULL || conn == NULL)
		return FALSE;

	dbus_connection_set_unix_user_function(conn, allow_user, NULL, NULL);

	nih_info (_("Connection from private client"));

	NIH_MUST (nih_dbus_object_new (NULL, conn,
	          "/org/linuxcontainers/cgmanager",
	          cgmanager_interfaces, NULL));

	return TRUE;
}

static void
client_disconnect (DBusConnection *conn)
{
	if (conn == NULL)
		return;

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
