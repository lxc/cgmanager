/* cgmanager
 *
 * Copyright © 2013 Stphane Graber
 * Author: Stphane Graber <stgraber@ubuntu.com>
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
#include <unistd.h>
#include <sys/mount.h>
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
#include <nih-dbus/dbus_object.h>
#include <nih-dbus/dbus_proxy.h>
#include <nih-dbus/dbus_error.h>

#include <sys/socket.h>

#include "cgmanager.h"
#include "fs.h"
#include "access_checks.h"

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

bool setns_pid_supported = false;
unsigned long mypidns;
bool setns_user_supported = false;
unsigned long myuserns;

int cgmanager_ping (void *data, NihDBusMessage *message, int junk)
{
	if (message == NULL) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"message was null");
		return -1;
	}

	return 0;
}

/* GetPidCgroup */
int get_pid_cgroup_main (const void *parent, const char *controller,
			 int target_pid, struct ucred c, char **output)
{
	char rcgpath[MAXPATHLEN], vcgpath[MAXPATHLEN];

	// Get r's current cgroup in rcgpath
	if (!compute_pid_cgroup(c.pid, controller, "", rcgpath)) {
		nih_error("Could not determine the requestor cgroup");
		return -1;
	}

	// Get v's cgroup in vcgpath
	if (!compute_pid_cgroup(target_pid, controller, "", vcgpath)) {
		nih_error("Could not determine the victim cgroup");
		return -1;
	}

	// Make sure v's cgroup is under r's
	int rlen = strlen(rcgpath);
	if (strncmp(rcgpath, vcgpath, rlen) != 0) {
		nih_error("v (%d)'s cgroup is not below r (%d)'s",
			(int)target_pid, (int)c.pid);
		return -1;
	}
	if (strlen(vcgpath) == rlen)
		*output = nih_strdup(parent, "/");
	else
		*output = nih_strdup(parent, vcgpath + rlen + 1);

	if (! *output)
		nih_return_no_memory_error(-1);

	return 0;
}

struct scm_sock_data {
	char *controller;
	char *cgroup;
	char *key;
	char *value;
	int step;
	struct ucred rcred;
	int fd;
	int recursive;
};

static void get_pid_scm_reader (struct scm_sock_data *data,
			NihIo *io, const char *buf, size_t len)
{
	const char *controller = data->controller;
	char *output = NULL;
	struct ucred ucred;
	pid_t target_pid;
	int ret;

	if (!get_nih_io_creds(io, &ucred)) {
		nih_error("failed to read ucred");
		goto out;
	}

	if (data->step == 0) {
		char b[1];
		b[0] = '1';
		// We need to fetch a second ucred
		memcpy(&data->rcred, &ucred, sizeof(struct ucred));
		data->step = 1;
		if (write(data->fd, b, 1) != 1) {
			nih_error("failed to write ucred");
			nih_io_shutdown(io);
			return;
		}
		return;
	}
	// we've read the second ucred, now we can proceed
	target_pid = ucred.pid;
	memcpy(&ucred, &data->rcred, sizeof(struct ucred));
	nih_info (_("GetPidCgroupScm: Client fd is: %d (pid=%d, uid=%d, gid=%d)"),
		  data->fd, ucred.pid, ucred.uid, ucred.gid);
	nih_info (_("Victim is pid=%d"), target_pid);

	if (!get_pid_cgroup_main(data, controller, target_pid, ucred, &output))
		ret = write(data->fd, output, strlen(output)+1);
	else
		ret = write(data->fd, &ucred, 0);  // kick the client
	if (ret < 0)
		nih_info("GetPidCgroupScm: Error writing final result to client");
out:
	nih_io_shutdown(io);
}

static void
scm_sock_close (struct scm_sock_data *data, NihIo *io)
{
	nih_assert (data);
	nih_assert (io);
	close (data->fd);
	nih_free (data);
	nih_free (io);
}
/*
 * This is one of the dbus callbacks.
 * Caller requests the cgroup of @pid in a given @controller
 */
int cgmanager_get_pid_cgroup_scm (void *data, NihDBusMessage *message,
			const char *controller, int sockfd)
{
	struct scm_sock_data *d;
        char buf[1];
	int optval = -1;

	if (setsockopt(sockfd, SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			     "Failed to set passcred: %s", strerror(errno));
		return -1;
	}
	d = nih_alloc(NULL, sizeof(*d));
	if (!d) {
		nih_dbus_error_raise_printf (DBUS_ERROR_NO_MEMORY,
			"Out of memory");
		return -1;
	}
	memset(d, 0, sizeof(*d));
	d->controller = nih_strdup(d, controller);
	d->step = 0;
	d->fd = sockfd;

	if (!nih_io_reopen(NULL, sockfd, NIH_IO_MESSAGE,
		(NihIoReader)get_pid_scm_reader,
		(NihIoCloseHandler) scm_sock_close,
		 NULL, d)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed to queue scm message: %s", strerror(errno));
		return -1;
	}

	buf[0] = '1';
	if (write(sockfd, buf, 1) != 1) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed to start write on scm fd: %s", strerror(errno));
		return -1;
	}
	return 0;
}

/* GetPidCgroup */
/*
 * This is one of the dbus callbacks.
 * Caller requests the cgroup of @pid in a given @controller
 */
int cgmanager_get_pid_cgroup (void *data, NihDBusMessage *message,
			const char *controller, int plain_pid, char **output)
{
	int fd = 0, ret;
	struct ucred ucred;
	socklen_t len;

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

	nih_info (_("GetPidCgroup: Client fd is: %d (pid=%d, uid=%d, gid=%d)"),
		  fd, ucred.pid, ucred.uid, ucred.gid);

	if (!is_same_pidns((int)ucred.pid)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
				"GetPidCgroup called from non-init namespace");
		return -1;
	}
	ret = get_pid_cgroup_main(message, controller, plain_pid, ucred,
				   output);
	if (ret) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
				"invalid request");
		return -1;
	}
	return 0;
}

/* MovePid */
/*
 * This is one of the dbus callbacks.
 * Caller requests moving a @pid to a particular cgroup identified
 * by the name (@cgroup) and controller type (@controller).
 */
int move_pid_main (const char *controller, char *cgroup,
		struct ucred r, int target_pid)
{
	char rcgpath[MAXPATHLEN], path[MAXPATHLEN];
	FILE *f;

	// verify that ucred.pid may move target_pid
	if (!may_move_pid(r.pid, r.uid, target_pid)) {
		nih_error("%d may not move %d", (int)r.pid, (int)r.pid);
		return -1;
	}

	if (cgroup[0] == '/' || cgroup[0] == '.') {
		// We could try to be accomodating, but let's not fool around right now
		nih_error("Bad requested cgroup path: %s", cgroup);
		return -1;
	}

	// Get r's current cgroup in rcgpath
	if (!compute_pid_cgroup(r.pid, controller, "", rcgpath)) {
		nih_error("Could not determine the requested cgroup");
		return -1;
	}
	/* rcgpath + / + cgroup + /tasks + \0 */
	if (strlen(rcgpath) + strlen(cgroup) > MAXPATHLEN+8) {
		nih_error("Path name too long");
		return -1;
	}
	strcpy(path, rcgpath);
	strncat(path, "/", MAXPATHLEN-1);
	strncat(path, cgroup, MAXPATHLEN-1);
	if (realpath_escapes(path, rcgpath)) {
		nih_error("Invalid path %s", path);
		return -1;
	}
	// is r allowed to descend under the parent dir?
	if (!may_access(r.pid, r.uid, r.gid, path, O_RDONLY)) {
		nih_error("pid %d (uid %d gid %d) may not write under %s",
			(int)r.pid, (int)r.uid, (int)r.gid, path);
		return -1;
	}
	// is r allowed to write to tasks file?
	strncat(path, "/tasks", MAXPATHLEN-1);
	if (!may_access(r.pid, r.uid, r.gid, path, O_WRONLY)) {
		nih_error("pid %d (uid %d gid %d) may not write under %s",
			(int)r.pid, (int)r.uid, (int)r.gid, path);
		return -1;
	}
	f = fopen(path, "w");
	if (!f) {
		nih_error("Failed to open %s", path);
		return -1;
	}
	if (fprintf(f, "%d\n", target_pid) < 0) {
		fclose(f);
		nih_error("Failed to open %s", path);
		return -1;
	}
	if (fclose(f) != 0) {
		nih_error("Failed to write %d to %s", (int)target_pid, path);
		return -1;
	}
	nih_info("%d moved to %s:%s by %d's request", (int)target_pid,
		controller, cgroup, (int)r.pid);
	return 0;
}

void move_pid_scm_reader (struct scm_sock_data *data,
		NihIo *io, const char *buf, size_t len)
{
	struct ucred ucred;
	pid_t target_pid;
	char b[1];

	if (!get_nih_io_creds(io, &ucred)) {
		nih_error("failed to read ucred");
		goto out;
	}

	if (data->step == 0) {
		b[0] = '1';
		// We need to fetch a second ucred
		memcpy(&data->rcred, &ucred, sizeof(struct ucred));
		data->step = 1;
		if (write(data->fd, b, 1) != 1) {
			nih_error("failed to read ucred");
			nih_io_shutdown(io);
			return;
		}
		return;
	}
	// we've read the second ucred, now we can proceed
	target_pid = ucred.pid;
	memcpy(&ucred, &data->rcred, sizeof(struct ucred));
	nih_info (_("MovePidScm: Client fd is: %d (pid=%d, uid=%d, gid=%d)"),
		  data->fd, ucred.pid, ucred.uid, ucred.gid);
	nih_info (_("Victim is pid=%d"), target_pid);

	*b = '0';
	if (move_pid_main(data->controller, data->cgroup, ucred, target_pid) == 0)
		*b = '1';
	if (write(data->fd, b, 1) < 0)
		nih_error("MovePidScm: Error writing final result to client");
out:
	nih_io_shutdown(io);
}
int cgmanager_move_pid_scm (void *data, NihDBusMessage *message,
			const char *controller, char *cgroup,
			int sockfd)
{
	struct scm_sock_data *d;
        char buf[1];
	int optval = -1;

	if (setsockopt(sockfd, SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			     "Failed to set passcred: %s", strerror(errno));
		return -1;
	}
	d = nih_alloc(NULL, sizeof(*d));
	if (!d) {
		nih_dbus_error_raise_printf (DBUS_ERROR_NO_MEMORY,
			"Out of memory");
		return -1;
	}
	memset(d, 0, sizeof(*d));
	d->controller = nih_strdup(d, controller);
	d->cgroup = nih_strdup(d, cgroup);
	d->step = 0;
	d->fd = sockfd;

	if (!nih_io_reopen(NULL, sockfd, NIH_IO_MESSAGE,
		(NihIoReader)move_pid_scm_reader,
		(NihIoCloseHandler) scm_sock_close,
		 NULL, d)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed to queue scm message: %s", strerror(errno));
		return -1;
	}
	buf[0] = '1';
	if (write(sockfd, buf, 1) != 1) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed to start write on scm fd: %s", strerror(errno));
		return -1;
	}
	return 0;
}

int cgmanager_move_pid (void *data, NihDBusMessage *message,
			const char *controller, char *cgroup, int plain_pid)
{
	int fd = 0, ret;
	struct ucred ucred;
	socklen_t len;

	nih_info("%s called, plain_pid is %d", __func__, plain_pid);
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

	nih_info (_("MovePid: Client fd is: %d (pid=%d, uid=%d, gid=%d)"),
		  fd, ucred.pid, ucred.uid, ucred.gid);

	ret = move_pid_main(controller, cgroup, ucred, plain_pid);
	if (ret)
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
		                             "invalid request");
	return ret;
}

/* 
 * This is one of the dbus callbacks.
 * Caller requests creating a new @cgroup name of type @controller.
 * @name is taken to be relative to the caller's cgroup and may not
 * start with / or .. .
 */
int create_main (const char *controller, char *cgroup, struct ucred ucred, int *existed)
{
	int ret;
	char rcgpath[MAXPATHLEN], path[MAXPATHLEN], dirpath[MAXPATHLEN];
	nih_local char *copy = NULL;
	size_t cgroup_len;
	char *p, *p2, oldp2;

	if (!cgroup || ! *cgroup)  // nothing to do
		return 0;
	if (cgroup[0] == '/' || cgroup[0] == '.') {
		// We could try to be accomodating, but let's not fool around right now
		nih_error("Bad requested cgroup path: %s", cgroup);
		return -1;
	}

	// TODO - support comma-separated list of controllers?  Not sure it's worth it

	// Get r's current cgroup in rcgpath
	if (!compute_pid_cgroup(ucred.pid, controller, "", rcgpath)) {
		nih_error("Could not determine the requested cgroup");
		return -1;
	}

	cgroup_len = strlen(cgroup);

	if (strlen(rcgpath) + cgroup_len > MAXPATHLEN) {
		nih_error("Path name too long");
		return -1;
	}
	copy = nih_strndup(NULL, cgroup, cgroup_len);
	if (!copy) {
		nih_error("Out of memory copying cgroup name");
		return -1;
	}

	strcpy(path, rcgpath);
	strcpy(dirpath, rcgpath);
	for (p=copy; *p; p = p2) {
		*existed = 0;
		for (p2=p; *p2 && *p2 != '/'; p2++);
		oldp2 = *p2;
		*p2 = '\0';
		if (strcmp(p, "..") == 0) {
			nih_error("Out of memory copying cgroup name");
			return -1;
		}
		strncat(path, "/", MAXPATHLEN-1);
		strncat(path, p, MAXPATHLEN-1);
		if (dir_exists(path)) {
			*existed = 1;
			// TODO - properly use execute perms
			if (!may_access(ucred.pid, ucred.uid, ucred.gid, path, O_RDONLY)) {
				nih_error("pid %d (uid %d gid %d) may not look under %s",
					(int)ucred.pid, (int)ucred.uid, (int)ucred.gid, path);
				return -1;
			}
			goto next;
		}
		if (!may_access(ucred.pid, ucred.uid, ucred.gid, dirpath, O_RDWR)) {
			nih_error("pid %d (uid %d gid %d) may not create under %s",
				(int)ucred.pid, (int)ucred.uid, (int)ucred.gid, dirpath);
			return -1;
		}
		ret = mkdir(path, 0755);
		if (ret < 0) {  // Should we ignore EEXIST?  Ok, but don't chown.
			if (errno == EEXIST) {
				*existed = 1;
				goto next;
			}
			nih_error("failed to create %s", path);
			return -1;
		}
		if (!chown_cgroup_path(path, ucred.uid, ucred.gid, true)) {
			nih_error("Failed to change ownership on %s to %d:%d",
				path, (int)ucred.uid, (int)ucred.gid);
			rmdir(path);
			return -1;
		}
		*existed = 0;
next:
		strncat(dirpath, "/", MAXPATHLEN-1);
		strncat(dirpath, p, MAXPATHLEN-1);
		*p2 = oldp2;
		if (*p2)
			p2++;
	}


	nih_info("Created %s for %d (%d:%d)", path, (int)ucred.pid,
		 (int)ucred.uid, (int)ucred.gid);
	return 0;
}

void create_scm_reader (struct scm_sock_data *data,
		NihIo *io, const char *buf, size_t len)
{
	struct ucred ucred;
	char b[1];
	int ret;
	int existed = 0;

	if (!get_nih_io_creds(io, &ucred)) {
		nih_error("failed to read ucred");
		goto out;
	}
	nih_info (_("CreateScm: Client fd is: %d (pid=%d, uid=%d, gid=%d)"),
		  data->fd, ucred.pid, ucred.uid, ucred.gid);

	ret = create_main(data->controller, data->cgroup, ucred, &existed);
	if (ret == 0)
		*b = existed ? '2' : '1';
	else
		*b = '0';
	if (write(data->fd, b, 1) < 0)
		nih_error("createScm: Error writing final result to client");
out:
	nih_io_shutdown(io);
}
int cgmanager_create_scm (void *data, NihDBusMessage *message,
		 const char *controller, char *cgroup, int sockfd)
{
	struct scm_sock_data *d;
        char buf[1];
	int optval = -1;

	if (setsockopt(sockfd, SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			     "Failed to set passcred: %s", strerror(errno));
		return -1;
	}
	d = nih_alloc(NULL, sizeof(*d));
	if (!d) {
		nih_dbus_error_raise_printf (DBUS_ERROR_NO_MEMORY,
			"Out of memory");
		return -1;
	}
	memset(d, 0, sizeof(*d));
	d->controller = nih_strdup(d, controller);
	d->cgroup = nih_strdup(d, cgroup);
	d->fd = sockfd;

	if (!nih_io_reopen(NULL, sockfd, NIH_IO_MESSAGE,
		(NihIoReader)create_scm_reader,
		(NihIoCloseHandler) scm_sock_close,
		 NULL, d)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed to queue scm message: %s", strerror(errno));
		return -1;
	}
	buf[0] = '1';
	if (write(sockfd, buf, 1) != 1) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed to start write on scm fd: %s", strerror(errno));
		return -1;
	}
	return 0;
}
int cgmanager_create (void *data, NihDBusMessage *message,
			 const char *controller, char *cgroup, int *existed)
{
	int fd = 0, ret;
	struct ucred ucred;
	socklen_t len;

	*existed = 0;
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

	nih_info (_("Create: Client fd is: %d (pid=%d, uid=%d, gid=%d)"),
		  fd, ucred.pid, ucred.uid, ucred.gid);

	ret = create_main(controller, cgroup, ucred, existed);
	if (ret)
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
		                             "invalid request");
	return ret;
}

/*
 * This is one of the dbus callbacks.
 * Caller requests chowning a cgroup @name in controller @cgroup to a
 * particular @uid.  The uid must be passed in as an scm_cred so the
 * kernel translates it for us.  @r must be root in its own user ns.
 *
 * If we are asked to chown /b to UID, then we will chown:
 * /b itself, /b/tasks, and /b/procs.  Any other files in /b will not be
 * chown.  UID can then create subdirs of /b, but not raise his limits.
 */
int chown_main (const char *controller,
		char *cgroup, struct ucred r, struct ucred v)
{
	char rcgpath[MAXPATHLEN];
	nih_local char *path = NULL;

	/* If caller is not root in his userns, then he can't chown, as
	 * that requires privilege over two uids */
	if (hostuid_to_ns(r.uid, r.pid) != 0) {
		nih_error("Chown requested by non-root uid %d", r.uid);
		return -1;
	}

	if (cgroup[0] == '/' || cgroup[0] == '.') {
		// We could try to be accomodating, but let's not fool around right now
		nih_error("Bad requested cgroup path: %s", cgroup);
		return -1;
	}

	// Get r's current cgroup in rcgpath
	if (!compute_pid_cgroup(r.pid, controller, "", rcgpath)) {
		nih_error("Could not determine the requested cgroup");
		return -1;
	}
	/* rcgpath + / + cgroup + \0 */
	if (strlen(rcgpath) + strlen(cgroup) > MAXPATHLEN+2) {
		nih_error("Path name too long");
		return -1;
	}
	path = nih_sprintf(NULL, "%s/%s", rcgpath, cgroup);
	if (!path) {
		nih_error("Out of memory calculating pathname");
		return -1;
	}
	if (realpath_escapes(path, rcgpath)) {
		nih_error("Invalid path %s", path);
		return -1;
	}
	// is r allowed to descend under the parent dir?
	if (!may_access(r.pid, r.uid, r.gid, path, O_RDONLY)) {
		nih_error("pid %d (uid %d gid %d) may not write under %s",
			(int)r.pid, (int)r.uid, (int)r.gid, path);
		return -1;
	}

	// does r have privilege over the cgroup dir?
	if (!may_access(r.pid, r.uid, r.gid, path, O_RDWR)) {
		nih_error("Pid %d may not chown %s\n", (int)r.pid, path);
		return -1;
	}

	// go ahead and chown it.
	if (!chown_cgroup_path(path, v.uid, v.gid, false)) {
		nih_error("Failed to change ownership on %s to %d:%d",
			path, (int)v.uid, (int)v.gid);
		return -1;
	}

	return 0;
}

void chown_scm_reader (struct scm_sock_data *data,
		NihIo *io, const char *buf, size_t len)
{
	struct ucred vcred;
	char b[1];

	if (!get_nih_io_creds(io, &vcred)) {
		nih_error("failed to read ucred");
		goto out;
	}

	if (data->step == 0) {
		b[0] = '1';
		// We need to fetch a second ucred
		memcpy(&data->rcred, &vcred, sizeof(struct ucred));
		data->step = 1;
		if (write(data->fd, b, 1) != 1) {
			nih_error("failed to read ucred");
			nih_io_shutdown(io);
			return;
		}
		return;
	}
	// we've read the second ucred, now we can proceed
	nih_info (_("ChownScm: Client fd is: %d (pid=%d, uid=%d, gid=%d)"),
		  data->fd, data->rcred.pid, data->rcred.uid, data->rcred.gid);
	nih_info (_("Victim is (uid=%d, gid=%d)"), vcred.uid, vcred.gid);

	*b = '0';
	if (chown_main(data->controller, data->cgroup, data->rcred, vcred) == 0)
		*b = '1';
	if (write(data->fd, b, 1) < 0)
		nih_error("ChownScm: Error writing final result to client");
out:
	nih_io_shutdown(io);
}
int cgmanager_chown_scm (void *data, NihDBusMessage *message,
			const char *controller, char *cgroup, int sockfd)
{
	struct scm_sock_data *d;
        char buf[1];
	int optval = -1;

	if (setsockopt(sockfd, SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			     "Failed to set passcred: %s", strerror(errno));
		return -1;
	}
	d = nih_alloc(NULL, sizeof(*d));
	if (!d) {
		nih_dbus_error_raise_printf (DBUS_ERROR_NO_MEMORY,
			"Out of memory");
		return -1;
	}
	memset(d, 0, sizeof(*d));
	d->controller = nih_strdup(d, controller);
	d->cgroup = nih_strdup(d, cgroup);
	d->step = 0;
	d->fd = sockfd;

	if (!nih_io_reopen(NULL, sockfd, NIH_IO_MESSAGE,
		(NihIoReader) chown_scm_reader,
		(NihIoCloseHandler) scm_sock_close,
		 NULL, d)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed to queue scm message: %s", strerror(errno));
		return -1;
	}
	buf[0] = '1';
	if (write(sockfd, buf, 1) != 1) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed to start write on scm fd: %s", strerror(errno));
		return -1;
	}
	return 0;
}

int cgmanager_chown (void *data, NihDBusMessage *message,
			const char *controller, char *cgroup, int uid, int gid)
{
	int fd = 0, ret;
	struct ucred ucred, vcred;
	socklen_t len;

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

	nih_info (_("Chown: Client fd is: %d (pid=%d, uid=%d, gid=%d)"),
		  fd, ucred.pid, ucred.uid, ucred.gid);

	if (!is_same_pidns((int)ucred.pid)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
				"chown called from non-init pid namespace");
		return -1;
	}
	if (!is_same_userns((int)ucred.pid)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
				"chown called from non-init user namespace");
		return -1;
	}

	vcred.pid = 0;
	vcred.uid = uid;
	vcred.gid = gid;

	ret = chown_main(controller, cgroup, ucred, vcred);
	if (ret)
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
		                             "invalid request");
	return ret;
}

/* 
 * This is one of the dbus callbacks.
 * Caller requests the value of a particular cgroup file.
 * @controller is the controller, @req_cgroup the cgroup name, and @key the
 * file being queried (i.e. memory.usage_in_bytes).  @req_cgroup is relative
 * to the caller's cgroup, unless it begins with '/' or '..'.
 *
 * XXX Should '/' be disallowed, only '..' allowed?  Otherwise callers can't
 * pretend to be the cgroup root which is annoying in itself
 */
int get_value_main (void *parent, const char *controller, const char *req_cgroup,
		                 const char *key, struct ucred ucred, char **value)
{
	char path[MAXPATHLEN];

	if (!compute_pid_cgroup(ucred.pid, controller, req_cgroup, path)) {
		nih_error("Could not determine the requested cgroup");
		return -1;
	}

	/* Check access rights to the cgroup directory */
	if (!may_access(ucred.pid, ucred.uid, ucred.gid, path, O_RDONLY)) {
		nih_error("Pid %d may not access %s\n", (int)ucred.pid, path);
		return -1;
	}

	/* append the filename */
	if (strlen(path) + strlen(key) + 2 > MAXPATHLEN) {
		nih_error("filename too long for cgroup %s key %s", path, key);
		return -1;
	}

	strncat(path, "/", MAXPATHLEN-1);
	strncat(path, key, MAXPATHLEN-1);

	/* Check access rights to the file itself */
	if (!may_access(ucred.pid, ucred.uid, ucred.gid, path, O_RDONLY)) {
		nih_error("Pid %d may not access %s\n", (int)ucred.pid, path);
		return -1;
	}

	/* read and return the value */
	*value = file_read_string(parent, path);
	if (!*value) {
		nih_error("Failed to read value from %s", path);
		return -1;
	}

	nih_info("Sending to client: %s", *value);
	return 0;
}
static void get_value_scm_reader (struct scm_sock_data *data,
			NihIo *io, const char *buf, size_t len)
{
	char *output = NULL;
	struct ucred ucred;
	int ret;

	if (!get_nih_io_creds(io, &ucred)) {
		nih_error("failed to read ucred");
		goto out;
	}

	nih_info (_("GetValueScm: Client fd is: %d (pid=%d, uid=%d, gid=%d)"),
		  data->fd, ucred.pid, ucred.uid, ucred.gid);

	if (!get_value_main(data, data->controller, data->cgroup, data->key, ucred, &output))
		ret = write(data->fd, output, strlen(output)+1);
	else
		ret = write(data->fd, &ucred, 0);  // kick the client
	if (ret < 0)
		nih_error("GetValueScm: Error writing final result to client");
out:
	nih_io_shutdown(io);
}
int cgmanager_get_value_scm (void *data, NihDBusMessage *message,
				 const char *controller, const char *req_cgroup,
		                 const char *key, int sockfd)
{
	struct scm_sock_data *d;
        char buf[1];
	int optval = -1;

	if (setsockopt(sockfd, SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			     "Failed to set passcred: %s", strerror(errno));
		return -1;
	}
	d = nih_alloc(NULL, sizeof(*d));
	if (!d) {
		nih_dbus_error_raise_printf (DBUS_ERROR_NO_MEMORY,
			"Out of memory");
		return -1;
	}
	memset(d, 0, sizeof(*d));
	d->controller = nih_strdup(d, controller);
	d->cgroup = nih_strdup(d, req_cgroup);
	d->key = nih_strdup(d, key);
	d->step = 0;
	d->fd = sockfd;

	if (!nih_io_reopen(NULL, sockfd, NIH_IO_MESSAGE,
		(NihIoReader)get_value_scm_reader,
		(NihIoCloseHandler) scm_sock_close,
		 NULL, d)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed to queue scm message: %s", strerror(errno));
		return -1;
	}
	buf[0] = '1';
	if (write(sockfd, buf, 1) != 1) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed to start write on scm fd: %s", strerror(errno));
		return -1;
	}
	return 0;

}
int cgmanager_get_value (void *data, NihDBusMessage *message,
				 const char *controller, const char *req_cgroup,
		                 const char *key, char **value)

{
	int fd = 0, ret;
	struct ucred ucred;
	socklen_t len;

	if (message == NULL) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Message was NULL");
		return -1;
	}

	if (!dbus_connection_get_socket(message->connection, &fd)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
		                             "Could not get client socket.");
		return -1;
	}

	len = sizeof(struct ucred);
	NIH_MUST (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &ucred, &len) != -1);

	nih_info (_("GetValue: Client fd is: %d (pid=%d, uid=%d, gid=%d)"),
		  fd, ucred.pid, ucred.uid, ucred.gid);

	ret = get_value_main(message, controller, req_cgroup, key, ucred, value);
	if (ret)
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
		                             "invalid request");
	return ret;
}

/* 
 * This is one of the dbus callbacks.
 * Caller requests that a particular cgroup @key be set to @value
 * @controller is the controller, @req_cgroup the cgroup name, and @key the
 * file being queried (i.e. memory.usage_in_bytes).  @req_cgroup is relative
 * to the caller's cgroup.
 */
int set_value_main (const char *controller, const char *req_cgroup,
		                 const char *key, const char *value, struct ucred ucred)

{
	char path[MAXPATHLEN];

	if (!compute_pid_cgroup(ucred.pid, controller, req_cgroup, path)) {
		nih_error("Could not determine the requested cgroup");
		return -1;
	}

	/* Check access rights to the cgroup directory */
	if (!may_access(ucred.pid, ucred.uid, ucred.gid, path, O_RDONLY)) {
		nih_error("Pid %d may not access %s\n", (int)ucred.pid, path);
		return -1;
	}

	/* append the filename */
	if (strlen(path) + strlen(key) + 2 > MAXPATHLEN) {
		nih_error("filename too long for cgroup %s key %s", path, key);
		return -1;
	}

	strncat(path, "/", MAXPATHLEN-1);
	strncat(path, key, MAXPATHLEN-1);

	/* Check access rights to the file itself */
	if (!may_access(ucred.pid, ucred.uid, ucred.gid, path, O_RDWR)) {
		nih_error("Pid %d may not access %s\n", (int)ucred.pid, path);
		return -1;
	}

	/* read and return the value */
	if (!set_value(path, value)) {
		nih_error("Failed to set value %s to %s", path, value);
		return -1;
	}

	return 0;
}
void set_value_scm_reader (struct scm_sock_data *data,
		NihIo *io, const char *buf, size_t len)
{
	struct ucred ucred;
	char b[1];

	if (!get_nih_io_creds(io, &ucred)) {
		nih_error("failed to read ucred");
		goto out;
	}

	nih_info (_("SetValueScm: Client fd is: %d (pid=%d, uid=%d, gid=%d)"),
		  data->fd, ucred.pid, ucred.uid, ucred.gid);

	*b = '0';
	if (set_value_main(data->controller, data->cgroup, data->key, data->value, ucred) == 0)
		*b = '1';
	if (write(data->fd, b, 1) < 0)
		nih_error("SetValueScm: Error writing final result to client");
out:
	nih_io_shutdown(io);
}
int cgmanager_set_value_scm (void *data, NihDBusMessage *message,
				 const char *controller, const char *req_cgroup,
		                 const char *key, const char *value, int sockfd)
{
	struct scm_sock_data *d;
        char buf[1];
	int optval = -1;

	if (setsockopt(sockfd, SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			     "Failed to set passcred: %s", strerror(errno));
		return -1;
	}
	d = nih_alloc(NULL, sizeof(*d));
	if (!d) {
		nih_dbus_error_raise_printf (DBUS_ERROR_NO_MEMORY,
			"Out of memory");
		return -1;
	}
	memset(d, 0, sizeof(*d));
	d->controller = nih_strdup(d, controller);
	d->cgroup = nih_strdup(d, req_cgroup);
	d->key = nih_strdup(d, key);
	d->value = nih_strdup(d, value);
	d->step = 0;
	d->fd = sockfd;

	if (!nih_io_reopen(NULL, sockfd, NIH_IO_MESSAGE,
		(NihIoReader)set_value_scm_reader,
		(NihIoCloseHandler) scm_sock_close,
		 NULL, d)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed to queue scm message: %s", strerror(errno));
		return -1;
	}
	buf[0] = '1';
	if (write(sockfd, buf, 1) != 1) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed to start write on scm fd: %s", strerror(errno));
		return -1;
	}
	return 0;
}
int cgmanager_set_value (void *data, NihDBusMessage *message,
				 const char *controller, const char *req_cgroup,
		                 const char *key, const char *value)

{
	int fd = 0, ret;
	struct ucred ucred;
	socklen_t len;

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

	nih_info (_("SetValue: Client fd is: %d (pid=%d, uid=%d, gid=%d)"),
		  fd, ucred.pid, ucred.uid, ucred.gid);

	ret = set_value_main(controller, req_cgroup, key, value, ucred);
	if (ret)
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
		                             "invalid request");
	return ret;
}

/*
 * Refuse any '..', and consolidate any '//'
 */
static bool normalize_path(char *path)
{
	if (strstr(path, ".."))
		return false;
	while ((path = strstr(path, "//")) != NULL) {
		char *p2 = path+1;
		while (*p2 == '/')
			p2++;
		memcpy(path, p2, strlen(p2)+1);
		path++;
	}
	return true;
}

/*
 * Recursively delete a cgroup.
 * Cgroup files can't be deleted, but are cleaned up when you remove the
 * containing directory.  A directory cannot be removed until all its
 * children are removed, and can't be removed if any tasks remain.
 *
 * We allow any task which may write under /a/b to delete any cgroups
 * under that, even if, say, it technically is not allowed to remove
 * /a/b/c/d/.
 */
static int recursive_rmdir(char *path)
{
	struct dirent dirent, *direntp;
	DIR *dir;
	char pathname[MAXPATHLEN];
	int failed = 0;

	dir = opendir(path);
	if (!dir) {
		nih_error("Failed to open dir %s for recursive deletion", path);
		return -1;
	}

	while (!readdir_r(dir, &dirent, &direntp)) {
		struct stat mystat;
		int rc;

		if (!direntp)
			break;
		if (!strcmp(direntp->d_name, ".") ||
		    !strcmp(direntp->d_name, ".."))
			continue;
		rc = snprintf(pathname, MAXPATHLEN, "%s/%s", path, direntp->d_name);
		if (rc < 0 || rc >= MAXPATHLEN) {
			failed = 1;
			continue;
		}
		rc = lstat(pathname, &mystat);
		if (rc) {
			failed = 1;
			continue;
		}
		if (S_ISDIR(mystat.st_mode)) {
			if (recursive_rmdir(pathname) < 0)
				failed = 1;
		}
	}

	if (closedir(dir) < 0)
		failed = 1;
	if (rmdir(path) < 0)
		failed = 1;

	return failed ? -1 : 0;
}

/* 
 * This is one of the dbus callbacks.
 * Caller requests creating a new @cgroup name of type @controller.
 * @name is taken to be relative to the caller's cgroup and may not
 * start with / or .. .
 */
int remove_main (const char *controller, char *cgroup, struct ucred ucred, int recursive, int *existed)
{
	char rcgpath[MAXPATHLEN], path[MAXPATHLEN];
	size_t cgroup_len;
	nih_local char *working = NULL, *copy = NULL;
	char *p;

	*existed = 1;
	if (!cgroup || ! *cgroup)  // nothing to do
		return 0;
	if (cgroup[0] == '/' || cgroup[0] == '.') {
		// We could try to be accomodating, but let's not fool around right now
		nih_error("Bad requested cgroup path: %s", cgroup);
		return -1;
	}

	// Get r's current cgroup in rcgpath
	if (!compute_pid_cgroup(ucred.pid, controller, "", rcgpath)) {
		nih_error("Could not determine the requested cgroup");
		return -1;
	}

	cgroup_len = strlen(cgroup);

	if (strlen(rcgpath) + cgroup_len > MAXPATHLEN) {
		nih_error("Path name too long");
		return -1;
	}

	if (!normalize_path(cgroup))
		return -1;

	working = nih_strdup(NULL, rcgpath);
	if (!working)
		return -1;
	if (!nih_strcat(&working, NULL, "/"))
		return -1;
	if (!nih_strcat(&working, NULL, cgroup))
		return -1;
	if (!dir_exists(working)) {
		*existed = 0;
		return 0;
	}
	*existed = 1;
	// must have write access to the parent dir
	if (!(copy = nih_strdup(NULL, working)))
		return -1;
	if (!(p = strrchr(copy, '/')))
		return -1;
	*p = '\0';
	if (!may_access(ucred.pid, ucred.uid, ucred.gid, copy, O_WRONLY)) {
		nih_error("pid %d uid %d gid %d may not remove %s",
			(int)ucred.pid, (int)ucred.uid, (int)ucred.gid, copy);
		return -1;
	}

	if (!recursive) {
		if (rmdir(working) < 0) {
			nih_error("Failed to remove %s: %s", working, strerror(errno));
			return -1;
		}
	} else if (recursive_rmdir(working) < 0)
			return -1;

	nih_info("Removed %s for %d (%d:%d)", path, (int)ucred.pid,
		 (int)ucred.uid, (int)ucred.gid);
	return 0;
}

void remove_scm_reader (struct scm_sock_data *data,
		NihIo *io, const char *buf, size_t len)
{
	struct ucred ucred;
	char b[1];
	int ret;
	int existed = 0;

	if (!get_nih_io_creds(io, &ucred)) {
		nih_error("failed to read ucred");
		goto out;
	}
	nih_info (_("RemoveScm: Client fd is: %d (pid=%d, uid=%d, gid=%d)"),
		  data->fd, ucred.pid, ucred.uid, ucred.gid);

	ret = remove_main(data->controller, data->cgroup, ucred, data->recursive, &existed);
	if (ret == 0)
		*b = existed ? '2' : '1';
	else
		*b = '0';
	if (write(data->fd, b, 1) < 0)
		nih_error("removeScm: Error writing final result to client");
out:
	nih_io_shutdown(io);
}
int cgmanager_remove_scm (void *data, NihDBusMessage *message,
		 const char *controller, char *cgroup, int recursive, int sockfd)
{
	struct scm_sock_data *d;
        char buf[1];
	int optval = -1;

	if (setsockopt(sockfd, SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			     "Failed to set passcred: %s", strerror(errno));
		return -1;
	}
	d = nih_alloc(NULL, sizeof(*d));
	if (!d) {
		nih_dbus_error_raise_printf (DBUS_ERROR_NO_MEMORY,
			"Out of memory");
		return -1;
	}
	memset(d, 0, sizeof(*d));
	d->controller = nih_strdup(d, controller);
	d->cgroup = nih_strdup(d, cgroup);
	d->fd = sockfd;
	d->recursive = recursive;

	if (!nih_io_reopen(NULL, sockfd, NIH_IO_MESSAGE,
		(NihIoReader)remove_scm_reader,
		(NihIoCloseHandler) scm_sock_close,
		 NULL, d)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed to queue scm message: %s", strerror(errno));
		return -1;
	}
	buf[0] = '1';
	if (write(sockfd, buf, 1) != 1) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed to start write on scm fd: %s", strerror(errno));
		return -1;
	}
	return 0;
}
int cgmanager_remove (void *data, NihDBusMessage *message,
			 const char *controller, char *cgroup, int recursive, int *existed)
{
	int fd = 0, ret;
	struct ucred ucred;
	socklen_t len;

	*existed = 0;
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

	nih_info (_("Remove: Client fd is: %d (pid=%d, uid=%d, gid=%d)"),
		  fd, ucred.pid, ucred.uid, ucred.gid);

	ret = remove_main(controller, cgroup, ucred, recursive, existed);
	if (ret)
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
		                             "invalid request");
	return ret;
}

/* 
 * This is one of the dbus callbacks.
 * Caller requests the number of tasks in @cgroup in @controller
 * returns nrpids, or -1 on error.
 */
int get_tasks_main (void *parent, const char *controller, char *cgroup, struct ucred ucred, int32_t **pids)
{
	char path[MAXPATHLEN];
	const char *key = "tasks";

	if (!cgroup || ! *cgroup)  // nothing to do
		return 0;
	if (!compute_pid_cgroup(ucred.pid, controller, cgroup, path)) {
		nih_error("Could not determine the requested cgroup");
		return -1;
	}

	/* Check access rights to the cgroup directory */
	if (!may_access(ucred.pid, ucred.uid, ucred.gid, path, O_RDONLY)) {
		nih_error("Pid %d may not access %s\n", (int)ucred.pid, path);
		return -1;
	}

	/* append the filename */
	if (strlen(path) + strlen(key) + 2 > MAXPATHLEN) {
		nih_error("filename too long for cgroup %s key %s", path, key);
		return -1;
	}

	strncat(path, "/", MAXPATHLEN-1);
	strncat(path, key, MAXPATHLEN-1);

	return file_read_pids(parent, path, pids);
}

void get_tasks_scm_reader (struct scm_sock_data *data,
		NihIo *io, const char *buf, size_t len)
{
	struct ucred ucred, pcred;
	int i, ret;
	int32_t *pids, nrpids;

	if (!get_nih_io_creds(io, &ucred)) {
		nih_error("failed to read ucred");
		goto out;
	}
	nih_info (_("GetTasksScm: Client fd is: %d (pid=%d, uid=%d, gid=%d)"),
		  data->fd, ucred.pid, ucred.uid, ucred.gid);

	ret = get_tasks_main(data, data->controller, data->cgroup, ucred, &pids);
	if (ret < 0) {
		nih_error("Error getting nrtasks for %s:%s for pid %d",
			data->controller, data->cgroup, ucred.pid);
		nih_io_shutdown(io);
		return;
	}
	nrpids = ret;
	if (write(data->fd, &nrpids, sizeof(int32_t)) != sizeof(int32_t)) {
		nih_error("get_tasks_scm: Error writing final result to client");
		goto out;
	}
	pcred.uid = 0; pcred.gid = 0;
	for (i=0; i<ret; i++) {
		pcred.pid = pids[i];
		if (send_creds(data->fd, pcred)) {
			nih_error("get_tasks_scm: error writing pids back to client");
			goto out;
		}
	}
out:
	nih_io_shutdown(io);
}
int cgmanager_get_tasks_scm (void *data, NihDBusMessage *message,
		 const char *controller, char *cgroup, int sockfd)
{
	struct scm_sock_data *d;
        char buf[1];
	int optval = -1;

	if (setsockopt(sockfd, SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			     "Failed to set passcred: %s", strerror(errno));
		return -1;
	}
	d = nih_alloc(NULL, sizeof(*d));
	if (!d) {
		nih_dbus_error_raise_printf (DBUS_ERROR_NO_MEMORY,
			"Out of memory");
		return -1;
	}
	memset(d, 0, sizeof(*d));
	d->controller = nih_strdup(d, controller);
	d->cgroup = nih_strdup(d, cgroup);
	d->fd = sockfd;

	if (!nih_io_reopen(NULL, sockfd, NIH_IO_MESSAGE,
		(NihIoReader)get_tasks_scm_reader,
		(NihIoCloseHandler) scm_sock_close,
		 NULL, d)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed to queue scm message: %s", strerror(errno));
		return -1;
	}
	buf[0] = '1';
	if (write(sockfd, buf, 1) != 1) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed to start write on scm fd: %s", strerror(errno));
		return -1;
	}
	return 0;
}
int cgmanager_get_tasks (void *data, NihDBusMessage *message,
			 const char *controller, char *cgroup, int32_t **pids, size_t *nrpids)
{
	int fd = 0, ret;
	struct ucred ucred;
	socklen_t len;
	int32_t *tmp;

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

	nih_info (_("GetTasks: Client fd is: %d (pid=%d, uid=%d, gid=%d)"),
		  fd, ucred.pid, ucred.uid, ucred.gid);

	ret = get_tasks_main(message, controller, cgroup, ucred, &tmp);
	if (ret >= 0) {
		*nrpids = ret;
		*pids = tmp;
		ret = 0;
	} else
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
		                             "invalid request");
	return ret;
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
	dbus_connection_set_allow_anonymous(conn, TRUE);

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

static inline int mkdir_cgmanager_dir(void)
{
	if (mkdir(CGMANAGER_DIR, 0755) == -1 && errno != EEXIST) {
		nih_error("Could not create %s", CGMANAGER_DIR);
		return false;
	}
	return true;
}

static bool daemon_running(void)
{
	DBusConnection *server_conn;

	server_conn = nih_dbus_connect(CGMANAGER_DBUS_PATH, NULL);
	if (server_conn) {
		dbus_connection_unref (server_conn);
		return true;
	}
	return false;
}

/*
 * We may decide to make the socket path customizable.  For now
 * just assume it is in /sys/fs/cgroup/ which has some special
 * consequences
 */
static bool setup_cgroup_dir(void)
{
	int ret;
	if (!dir_exists(CGDIR)) {
		nih_debug(CGDIR " does not exist");
		return false;
	}
	if (daemon_running()) {
		nih_error("cgmanager is already running");
		return false;
	}
	if (file_exists(CGMANAGER_SOCK)) {
		if (unlink(CGMANAGER_SOCK) < 0) {
			nih_error("failed to delete stale cgmanager socket");
			return false;
		}
	}
	/* Check that /sys/fs/cgroup is writeable, else mount a tmpfs */
	unlink(CGPROBE);
	ret = creat(CGPROBE, O_RDWR);
	if (ret >= 0) {
		close(ret);
		unlink(CGPROBE);
		return mkdir_cgmanager_dir();
	}
	ret = mount("cgroup", CGDIR, "tmpfs", 0, "size=10000");
	if (ret) {
		nih_debug("Failed to mount tmpfs on %s: %s",
			CGDIR, strerror(errno));
		return false;
	}
	nih_debug("Mounted tmpfs onto %s", CGDIR);
	return mkdir_cgmanager_dir();
}

int
main (int   argc,
      char *argv[])
{
	char **             args;
	int                 ret;
	DBusServer *        server;
	struct stat sb;

	nih_main_init (argv[0]);

	nih_option_set_synopsis (_("Control group manager"));
	nih_option_set_help (_("The cgroup manager daemon"));

	args = nih_option_parser (NULL, argc, argv, options, FALSE);
	if (! args)
		exit (1);

	if (!setup_cgroup_dir()) {
		nih_fatal("Failed to set up cgmanager socket");
		exit(1);
	}

	/* Setup the DBus server */
	server = nih_dbus_server (CGMANAGER_DBUS_PATH, client_connect,
	                          client_disconnect);
	nih_assert (server != NULL);

	if (setup_cgroup_mounts() < 0) {
		nih_fatal ("Failed to set up cgroup mounts");
		exit(1);
	}

	if (stat("/proc/self/ns/pid", &sb) == 0) {
		mypidns = read_pid_ns_link(getpid());
		setns_pid_supported = true;
	}

	if (stat("/proc/self/ns/user", &sb) == 0) {
		myuserns = read_user_ns_link(getpid());
		setns_user_supported = true;
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
