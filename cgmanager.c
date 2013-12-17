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

int cgmanager_ping (void *data, NihDBusMessage *message, const char *controller)
{
	if (message == NULL) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"message was null");
		return -1;
	}

	return 0;
}

/* getPidCgroup */
int get_pid_cgroup_main (NihDBusMessage *message, const char *controller,
			 int target_pid, struct ucred c, char **output)
{
	char rcgpath[MAXPATHLEN], vcgpath[MAXPATHLEN];

	// Get r's current cgroup in rcgpath
	if (!compute_pid_cgroup(c.pid, controller, "", rcgpath)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Could not determine the requestor cgroup");
		return -1;
	}

	// Get v's cgroup in vcgpath
	if (!compute_pid_cgroup(target_pid, controller, "", vcgpath)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Could not determine the victim cgroup");
		return -1;
	}

	// Make sure v's cgroup is under r's
	int rlen = strlen(rcgpath);
	if (strncmp(rcgpath, vcgpath, rlen) != 0) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"v (%d)'s cgroup is not below r (%d)'s",
			(int)target_pid, (int)c.pid);
		return -1;
	}
	if (strlen(vcgpath) == rlen)
		*output = nih_strdup(message, "/");
	else
		*output = nih_strdup(message, vcgpath + rlen + 1);

	if (! *output)
		nih_return_no_memory_error(-1);

	return 0;
}

/*
 * This is one of the dbus callbacks.
 * Caller requests the cgroup of @pid in a given @controller
 */
int cgmanager_get_pid_cgroup_scm (void *data, NihDBusMessage *message,
			const char *controller, int sockfd, char **output)
{
	struct ucred ucred;
	pid_t target_pid;

	get_scm_creds(sockfd, &ucred.uid, &ucred.gid, &ucred.pid);
	nih_info (_("Client fd is: %d (pid=%d, uid=%d, gid=%d)"),
		  sockfd, ucred.pid, ucred.uid, ucred.gid);
	target_pid = get_scm_pid(sockfd);
	close(sockfd);

	if (target_pid == -1) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Could not retrieve pid from socket");
		return -1;
	}

	return get_pid_cgroup_main(message, controller, target_pid,
				   ucred, output);
}

/* getPidCgroup */
/*
 * This is one of the dbus callbacks.
 * Caller requests the cgroup of @pid in a given @controller
 */
int cgmanager_get_pid_cgroup (void *data, NihDBusMessage *message,
			const char *controller, int plain_pid, char **output)
{
	int fd = 0;
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

	nih_info (_("Client fd is: %d (pid=%d, uid=%d, gid=%d)"),
		  fd, ucred.pid, ucred.uid, ucred.gid);

	if (!is_same_pidns((int)ucred.pid)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
				"getPidCgroup called from non-init namespace");
		return -1;
	}
	return get_pid_cgroup_main(message, controller, plain_pid, ucred,
				   output);
}

/* movePid */
/*
 * This is one of the dbus callbacks.
 * Caller requests moving a @pid to a particular cgroup identified
 * by the name (@cgroup) and controller type (@controller).
 */
int move_pid_main (NihDBusMessage *message, const char *controller, char *cgroup,
		struct ucred r, int target_pid,  int *ok)
{
	char rcgpath[MAXPATHLEN], path[MAXPATHLEN];
	FILE *f;

	// verify that ucred.pid may move target_pid
	if (!may_move_pid(r.pid, r.uid, target_pid)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
					     "%d may not move %d", (int)r.pid,
					     (int)r.pid);
		return -1;
	}

	if (cgroup[0] == '/' || cgroup[0] == '.') {
		// We could try to be accomodating, but let's not fool around right now
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Bad requested cgroup path: %s", cgroup);
		return -1;
	}

	// Get r's current cgroup in rcgpath
	if (!compute_pid_cgroup(r.pid, controller, "", rcgpath)) {
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
	if (realpath_escapes(path, rcgpath)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Invalid path %s", path);
		return -1;
	}
	// is r allowed to descend under the parent dir?
	if (!may_access(r.pid, r.uid, r.gid, path, O_RDONLY)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"pid %d (uid %d gid %d) may not write under %s",
			(int)r.pid, (int)r.uid, (int)r.gid, path);
		return -1;
	}
	// is r allowed to write to tasks file?
	strncat(path, "/tasks", MAXPATHLEN-1);
	if (!may_access(r.pid, r.uid, r.gid, path, O_WRONLY)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"pid %d (uid %d gid %d) may not write under %s",
			(int)r.pid, (int)r.uid, (int)r.gid, path);
		return -1;
	}
	f = fopen(path, "w");
	if (!f) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed to open %s", path);
		return -1;
	}
	if (fprintf(f, "%d\n", target_pid) < 0) {
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
		controller, cgroup, (int)r.pid);
	*ok = 1;
	return 0;
}

int cgmanager_move_pid_scm (void *data, NihDBusMessage *message,
			const char *controller, char *cgroup,
			int sockfd, int *ok)
{
	struct ucred ucred;
	pid_t target_pid;

	*ok = -1;
	if (message == NULL) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"message was null");
		return -1;
	}

	get_scm_creds(sockfd, &ucred.uid, &ucred.gid, &ucred.pid);
	target_pid = get_scm_pid(sockfd);
	close(sockfd);

	if (target_pid == -1) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Could not get target pid from socket");
		return -1;
	}

	return move_pid_main(message, controller, cgroup, ucred, target_pid, ok);
}

int cgmanager_move_pid (void *data, NihDBusMessage *message,
			const char *controller, char *cgroup, int plain_pid,
			int *ok)
{
	int fd = 0;
	struct ucred ucred;
	socklen_t len;

	nih_info("%s called, plain_pid is %d", __func__, plain_pid);
	*ok = -1;
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

	return move_pid_main(message, controller, cgroup, ucred, plain_pid, ok);
}

/* 
 * This is one of the dbus callbacks.
 * Caller requests creating a new @cgroup name of type @controller.
 * @name is taken to be relative to the caller's cgroup and may not
 * start with / or .. .
 */
int create_main (NihDBusMessage *message, const char *controller, char *cgroup, struct ucred ucred)
{
	int ret;
	char rcgpath[MAXPATHLEN], path[MAXPATHLEN], *fnam, *dnam;
	nih_local char *copy = NULL;
	size_t cgroup_len;

	if (message == NULL) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"message was null");
		return -1;
	}

	if (!cgroup || ! *cgroup)  // nothing to do
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

	cgroup_len = strlen(cgroup);

	if (strlen(rcgpath) + cgroup_len > MAXPATHLEN) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Path name too long");
		return -1;
	}
	copy = nih_strndup(NULL, cgroup, cgroup_len);
	if (!copy) {
		nih_dbus_error_raise_printf (DBUS_ERROR_NO_MEMORY,
			"Out of memory copying cgroup name");
		return -1;
	}
	fnam = basename(copy);
	dnam = dirname(copy);
	strcpy(path, rcgpath);
	if (strcmp(dnam, ".") != 0) {
		// verify that the real path is below the controller path
		strncat(path, "/", MAXPATHLEN-1);
		strncat(path, dnam, MAXPATHLEN-1);
		if (realpath_escapes(path, rcgpath)) {
			nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
				"Invalid path %s", path);
			return -1;
		}
	}

	// is r allowed to create under the parent dir?
	if (!may_access(ucred.pid, ucred.uid, ucred.gid, path, O_RDWR)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"pid %d (uid %d gid %d) may not create under %s",
			(int)ucred.pid, (int)ucred.uid, (int)ucred.gid, path);
		return -1;
	}
	strncat(path, "/", MAXPATHLEN-1);
	strncat(path, fnam, MAXPATHLEN-1);
	ret = mkdir(path, 0755);
	if (ret < 0) {  // Should we ignore EEXIST?  Ok, but don't chown.
		if (errno == EEXIST)
			return 0;
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"failed to create %s", path);
		return -1;
	}
	if (!chown_cgroup_path(path, ucred.uid, ucred.gid, true)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed to change ownership on %s to %d:%d",
			path, (int)ucred.uid, (int)ucred.gid);
		rmdir(path);
		return -1;
	}

	nih_info("Created %s for %d (%d:%d)", path, (int)ucred.pid,
		 (int)ucred.uid, (int)ucred.gid);
	return 0;
}
int cgmanager_create_scm (void *data, NihDBusMessage *message,
			 const char *controller, char *cgroup, int sockfd)
{
	struct ucred ucred;

	if (message == NULL) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"message was null");
		return -1;
	}

	/*
	 * to send these scm credentials, caller must have had privilege
	 */
	get_scm_creds(sockfd, &ucred.uid, &ucred.gid, &ucred.pid);
	close(sockfd);
	nih_info (_("Client fd is: %d (pid=%d, uid=%d, gid=%d)"),
		  sockfd, ucred.pid, ucred.uid, ucred.gid);
	return create_main(message, controller, cgroup, ucred);
}
int cgmanager_create (void *data, NihDBusMessage *message,
				 const char *controller, char *cgroup)
{
	int fd = 0;
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

	nih_info (_("Client fd is: %d (pid=%d, uid=%d, gid=%d)"),
		  fd, ucred.pid, ucred.uid, ucred.gid);

	return create_main(message, controller, cgroup, ucred);
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
 *
 * On success, ok will be sent with value 1.  On failure, -1.
 */
int chown_cgroup_main (NihDBusMessage *message, const char *controller,
		char *cgroup, struct ucred r, struct ucred v, int *ok)
{
	char rcgpath[MAXPATHLEN];
	nih_local char *path = NULL;

	*ok = -1;

	/* If caller is not root in his userns, then he can't chown, as
	 * that requires privilege over two uids */
	if (hostuid_to_ns(r.uid, r.pid) != 0) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Chown requested by non-root uid %d", r.uid);
		return -1;
	}

	if (cgroup[0] == '/' || cgroup[0] == '.') {
		// We could try to be accomodating, but let's not fool around right now
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Bad requested cgroup path: %s", cgroup);
		return -1;
	}

	// Get r's current cgroup in rcgpath
	if (!compute_pid_cgroup(r.pid, controller, "", rcgpath)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Could not determine the requested cgroup");
		return -1;
	}
	/* rcgpath + / + cgroup + \0 */
	if (strlen(rcgpath) + strlen(cgroup) > MAXPATHLEN+2) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Path name too long");
		return -1;
	}
	path = nih_sprintf(NULL, "%s/%s", rcgpath, cgroup);
	if (!path) {
		nih_dbus_error_raise_printf (DBUS_ERROR_NO_MEMORY,
			"Out of memory calculating pathname");
		return -1;
	}
	if (realpath_escapes(path, rcgpath)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Invalid path %s", path);
		return -1;
	}
	// is r allowed to descend under the parent dir?
	if (!may_access(r.pid, r.uid, r.gid, path, O_RDONLY)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"pid %d (uid %d gid %d) may not write under %s",
			(int)r.pid, (int)r.uid, (int)r.gid, path);
		return -1;
	}

	// does r have privilege over the cgroup dir?
	if (!may_access(r.pid, r.uid, r.gid, path, O_RDWR)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Pid %d may not chown %s\n", (int)r.pid, path);
		return -1;
	}

	// go ahead and chown it.
	if (!chown_cgroup_path(path, v.uid, v.gid, false))
		return -1;

	*ok = 1;
	return 0;
}

int cgmanager_chown_cgroup_scm (void *data, NihDBusMessage *message,
			const char *controller, char *cgroup, int sockfd,
			int *ok)
{
	int fd = 0;
	struct ucred ucred, vcred;

	*ok = -1;
	if (message == NULL) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"message was null");
		return -1;
	}

	get_scm_creds(sockfd, &ucred.uid, &ucred.gid, &ucred.pid);
	get_scm_creds(sockfd, &vcred.uid, &vcred.gid, &vcred.pid);
	close(sockfd);

	if (vcred.pid == -1) {
		nih_dbus_error_raise_printf(DBUS_ERROR_INVALID_ARGS,
			"Could not calculate desired uid and gid");
		return -1;
	}

	nih_info (_("Client fd is: %d (pid=%d, uid=%d, gid=%d)"),
		  fd, ucred.pid, ucred.uid, ucred.gid);

	return chown_cgroup_main(message, controller, cgroup, ucred, vcred, ok);
}

int cgmanager_chown_cgroup (void *data, NihDBusMessage *message,
			const char *controller, char *cgroup, int uid, int gid,
			int *ok)
{
	int fd = 0;
	struct ucred ucred, vcred;
	socklen_t len;

	*ok = -1;
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

	return chown_cgroup_main(message, controller, cgroup, ucred, vcred, ok);
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
int get_value_main (NihDBusMessage *message, const char *controller, const char *req_cgroup,
		                 const char *key, struct ucred ucred, char **value)
{
	char path[MAXPATHLEN];

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
	*value = file_read_string(message, path);
	if (!*value) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed to read value from %s", path);
		return -1;
	}

	nih_info("Sending to client: %s", *value);
	return 0;
}
int cgmanager_get_value_scm (void *data, NihDBusMessage *message,
				 const char *controller, const char *req_cgroup,
		                 const char *key, int sockfd, char **value)
{
	struct ucred ucred;

	if (message == NULL) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Message was NULL");
		return -1;
	}

	/*
	 * to send these scm credentials, caller must have had privilege
	 */
	get_scm_creds(sockfd, &ucred.uid, &ucred.gid, &ucred.pid);
	close(sockfd);
	nih_info (_("Client fd is: %d (pid=%d, uid=%d, gid=%d)"),
		  sockfd, ucred.pid, ucred.uid, ucred.gid);

	return get_value_main(message, controller, req_cgroup, key, ucred, value);

}
int cgmanager_get_value (void *data, NihDBusMessage *message,
				 const char *controller, const char *req_cgroup,
		                 const char *key, char **value)

{
	int fd = 0;
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

	nih_info (_("Client fd is: %d (pid=%d, uid=%d, gid=%d)"),
		  fd, ucred.pid, ucred.uid, ucred.gid);

	return get_value_main(message, controller, req_cgroup, key, ucred, value);
}

/* 
 * This is one of the dbus callbacks.
 * Caller requests that a particular cgroup @key be set to @value
 * @controller is the controller, @req_cgroup the cgroup name, and @key the
 * file being queried (i.e. memory.usage_in_bytes).  @req_cgroup is relative
 * to the caller's cgroup.
 *
 * @ok is set to 1 if succeeds, -1 otherwise
 */
int set_value_main (NihDBusMessage *message, const char *controller, const char *req_cgroup,
		                 const char *key, const char *value, struct ucred ucred, int *ok)

{
	char path[MAXPATHLEN];

	*ok = -1;

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
	if (!may_access(ucred.pid, ucred.uid, ucred.gid, path, O_RDWR)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Pid %d may not access %s\n", (int)ucred.pid, path);
		return -1;
	}

	/* read and return the value */
	if (!set_value(path, value)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed to set value %s to %s", path, value);
		return -1;
	}

	*ok = 1;
	return 0;
}
int cgmanager_set_value_scm (void *data, NihDBusMessage *message,
				 const char *controller, const char *req_cgroup,
		                 const char *key, const char *value, int sockfd, int *ok)

{
	struct ucred ucred;

	*ok = -1;

	if (message == NULL) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Message was NULL");
		return -1;
	}

	/*
	 * to send these scm credentials, caller must have had privilege
	 */
	get_scm_creds(sockfd, &ucred.uid, &ucred.gid, &ucred.pid);
	close(sockfd);
	nih_info (_("Client fd is: %d (pid=%d, uid=%d, gid=%d)"),
		  sockfd, ucred.pid, ucred.uid, ucred.gid);

	return set_value_main(message, controller, req_cgroup, key, value, ucred, ok);
}
int cgmanager_set_value (void *data, NihDBusMessage *message,
				 const char *controller, const char *req_cgroup,
		                 const char *key, const char *value, int *ok)

{
	int fd = 0;
	struct ucred ucred;
	socklen_t len;

	*ok = -1;

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

	return set_value_main(message, controller, req_cgroup, key, value, ucred, ok);
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

	/* Setup the DBus server */
	server = nih_dbus_server ("unix:path=/tmp/cgmanager", client_connect,
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
