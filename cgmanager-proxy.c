/* cgmanager-proxy
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
#include <nih-dbus/dbus_message.h>

#include <sys/socket.h>

#include "cgmanager.h"
#include "fs.h"
#include "access_checks.h"

#include "org.linuxcontainers.cgmanager.h"

#define PACKAGE_NAME "cgmanager"
#define PACKAGE_VERSION "0.0"
#define PACKAGE_BUGREPORT ""

DBusConnection *server_conn;

int setup_proxy(void)
{
	bool exists_upper = false, exists_lower = false;

	/*
	 * If /sys/fs/cgroup/cgmanager.lower exists,
	 *    if /sys/fs/cgroup/cgmanager exists, then exit (proxy already running)
	 *    start up, connect to .lower
	 * else
	 *    if /sys/fs/cgroup/cgmanager exists, move it to /sys/fs/cgroup/cgmanager.lower
	 *    start up and connect to .lower
	 */
	server_conn = nih_dbus_connect(CGMANAGER_DBUS_PATH, NULL);
	if (server_conn) {
		exists_upper = true;
		dbus_connection_unref (server_conn);
	}
	server_conn = nih_dbus_connect(CGPROXY_DBUS_PATH, NULL);
	if (server_conn) {
		exists_lower = true;
	}
	if (exists_upper && exists_lower) {
		dbus_connection_unref (server_conn);
		nih_error("proxy already running");
		return -1;  // proxy already running
	}
	if (exists_lower)
		// we've got the sock we need, all set.
		return 0;
	if (exists_upper) {
		//move /sys/fs/cgroup/cgmanager to /sys/fs/cgroup/cgmanager.lower
		if (mkdir(CGPROXY_DIR, 0755) < 0 && errno != EEXIST) {
			nih_error("failed to create lower sock");
			return -1;
		}
		if (mount(CGMANAGER_DIR, CGPROXY_DIR, "none", MS_MOVE, 0) < 0) {
			nih_error("unable to rename the socket");
			return -1;
		}
	}
	server_conn = nih_dbus_connect(CGPROXY_DBUS_PATH, NULL);
	return 0;
}

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


void send_dummy_msg(DBusConnection *conn)
{
	DBusMessage *message = NULL;
	DBusMessageIter iter;
	int a;
	message = dbus_message_new_method_call(dbus_bus_get_unique_name(conn),
			"/org/linuxcontainers/cgmanager",
			"org.linuxcontainers.cgmanager0_0", "ping");
	dbus_message_set_no_reply(message, TRUE);
	dbus_message_iter_init_append(message, &iter);
        if (! dbus_message_iter_append_basic (&iter, DBUS_TYPE_INT32, &a)) {
                nih_error_raise_no_memory ();
                return;
        }
	dbus_connection_send(conn, message, NULL);
	dbus_connection_flush(conn);
	dbus_message_unref(message);
}

int get_pid_cgroup_main (void *parent, const char *controller,
		struct ucred ucred, struct ucred vcred, char **output)
{
	char buf[1];
	DBusMessage *message = NULL;
	DBusMessageIter iter;
	int sv[2], ret = -1, optval = 1;
	dbus_uint32_t serial;;

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
		nih_error("Error creating socketpair: %s", strerror(errno));
		return -1;
	}
	if (setsockopt(sv[1], SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
		nih_error("setsockopt: %s", strerror(errno));
		goto out;
	}
	if (setsockopt(sv[0], SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
		nih_error("setsockopt: %s", strerror(errno));
		goto out;
	}

	message = dbus_message_new_method_call(dbus_bus_get_unique_name(server_conn),
			"/org/linuxcontainers/cgmanager",
			"org.linuxcontainers.cgmanager0_0", "getPidCgroupScm");

	dbus_message_iter_init_append(message, &iter);
        if (! dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &controller)) {
                nih_error_raise_no_memory ();
                goto out;
        }
	if (! dbus_message_iter_append_basic (&iter, DBUS_TYPE_UNIX_FD, &sv[1])) {
		nih_error_raise_no_memory ();
		goto out;
	}

	if (!dbus_connection_send(server_conn, message, &serial)) {
		nih_error("failed to send dbus message");
		goto out;
	}
	dbus_connection_flush(server_conn);
	if (message) {
		dbus_message_unref(message);
		message = NULL;
	}

	if (read(sv[0], buf, 1) != 1) {
		nih_error("Error getting reply from server over socketpair");
		goto out;
	}
	if (send_creds(sv[0], ucred)) {
		nih_error("Error sending pid over SCM_CREDENTIAL");
		goto out;
	}
	if (read(sv[0], buf, 1) != 1) {
		nih_error("Error getting reply from server over socketpair");
		goto out;
	}
	if (send_creds(sv[0], vcred)) {
		nih_error("Error sending pid over SCM_CREDENTIAL");
		goto out;
	}
	char s[MAXPATHLEN];
	memset(s, 0, MAXPATHLEN);
	if (read(sv[0], s, MAXPATHLEN) <= 0)
		nih_error("Error reading result from cgmanager");
	else {
		*output = nih_strdup(parent, s);
		ret = 0;
	}
out:
	close(sv[0]);
	close(sv[1]);
	if (message)
		dbus_message_unref(message);
	return ret;
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

static void
scm_sock_close (struct scm_sock_data *data, NihIo *io)
{
	nih_assert (data);
	nih_assert (io);
	close (data->fd);
	nih_free (data);
	nih_free (io);
}

static void get_pid_scm_reader (struct scm_sock_data *data,
			NihIo *io, const char *buf, size_t len)
{
	const char *controller = data->controller;
	char *output = NULL;
	struct ucred vcred;
	int ret;

	if (!get_nih_io_creds(io, &vcred)) {
		nih_error("failed to read ucred");
		goto out;
	}

	if (data->step == 0) {
		char b[1];
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
	nih_info (_("Client fd is: %d (pid=%d, uid=%d, gid=%d)"),
		  data->fd, data->rcred.pid, data->rcred.uid, data->rcred.gid);
	nih_info (_("Victim is pid=%d"), vcred.pid);

	if (!get_pid_cgroup_main(data, controller, data->rcred, vcred, &output))
		ret = write(data->fd, output, strlen(output));
	else
		ret = write(data->fd, &vcred, 0);  // kick the client
	if (ret < 0)
		nih_error("getPidCgroupScm: Error writing final result to client");
out:
	nih_io_shutdown(io);
}
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

int cgmanager_get_pid_cgroup (void *data, NihDBusMessage *message,
			const char *controller, int plain_pid, char **output)
{
	struct ucred ucred, vcred;
	int fd, ret;
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
	vcred.pid = plain_pid;
	vcred.uid = 0; vcred.gid = 0; // cgmanager ignores these
	if (!setns_pid_supported) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"kernel too old, use getPidCgroupScm");
		return -1;
	}
	if (!is_same_pidns(ucred.pid)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"requestor is in a different namespace from cgproxy");
		return -1;
	}
	ret = get_pid_cgroup_main(message, controller, ucred, vcred, output);
	if (ret) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
				"invalid request");
		return -1;
	}
	return 0;
}

/*
 * This is one of the dbus callbacks.
 * Caller requests moving a @pid to a particular cgroup identified
 * by the name (@cgroup) and controller type (@controller).
 */
int move_pid_main (const char *controller, char *cgroup,
			struct ucred ucred, struct ucred vcred)
{
	char buf[1];
	DBusMessage *message = NULL;
	DBusMessageIter iter;
	int sv[2], ret = -1, optval = 1;
	dbus_uint32_t serial;;

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
		nih_error("Error creating socketpair: %s", strerror(errno));
		return -1;
	}
	if (setsockopt(sv[1], SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
		nih_error("setsockopt: %s", strerror(errno));
		goto out;
	}
	if (setsockopt(sv[0], SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
		nih_error("setsockopt: %s", strerror(errno));
		goto out;
	}

	message = dbus_message_new_method_call(dbus_bus_get_unique_name(server_conn),
			"/org/linuxcontainers/cgmanager",
			"org.linuxcontainers.cgmanager0_0", "movePidScm");

	dbus_message_iter_init_append(message, &iter);
        if (! dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &controller)) {
                nih_error_raise_no_memory ();
                goto out;
        }
        if (! dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &cgroup)) {
                nih_error_raise_no_memory ();
                goto out;
        }
	if (! dbus_message_iter_append_basic (&iter, DBUS_TYPE_UNIX_FD, &sv[1])) {
		nih_error_raise_no_memory ();
		goto out;
	}

	if (!dbus_connection_send(server_conn, message, &serial)) {
		nih_error("failed to send dbus message");
		goto out;
	}
	dbus_connection_flush(server_conn);
	if (message) {
		dbus_message_unref(message);
		message = NULL;
	}

	if (read(sv[0], buf, 1) != 1) {
		nih_error("Error getting reply from server over socketpair");
		goto out;
	}
	if (send_creds(sv[0], ucred)) {
		nih_error("Error sending pid over SCM_CREDENTIAL");
		goto out;
	}
	if (read(sv[0], buf, 1) != 1) {
		nih_error("Error getting reply from server over socketpair");
		goto out;
	}
	if (send_creds(sv[0], vcred)) {
		nih_error("Error sending pid over SCM_CREDENTIAL");
		goto out;
	}
	if (read(sv[0], buf, 1) == 1 && *buf == '1')
		ret = 0;
out:
	close(sv[0]);
	close(sv[1]);
	if (message)
		dbus_message_unref(message);
	return ret;
}
void move_pid_scm_reader (struct scm_sock_data *data,
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
	nih_info (_("Client fd is: %d (pid=%d, uid=%d, gid=%d)"),
		  data->fd, data->rcred.pid, data->rcred.uid, data->rcred.gid);
	nih_info (_("Victim is pid=%d"), vcred.pid);

	*b = '0';
	if (move_pid_main(data->controller, data->cgroup, data->rcred, vcred) == 0)
		*b = '1';
	if (write(data->fd, b, 1) < 0)
		nih_error("movePidScm: Error writing final result to client");
out:
	nih_io_shutdown(io);
}
int cgmanager_move_pid_scm (void *data, NihDBusMessage *message,
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
	struct ucred ucred, vcred;
	int fd, ret;
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
	vcred.pid = plain_pid;
	vcred.uid = 0; vcred.gid = 0; // cgmanager ignores these
	if (!setns_pid_supported) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"kernel too old, use movePidScm");
		return -1;
	}
	if (!is_same_pidns(ucred.pid)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"requestor is in a different namespace from cgproxy");
		return -1;
	}
	ret = move_pid_main(controller, cgroup, ucred, vcred);
	if (ret) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
				"invalid request");
		return -1;
	}
	return 0;
}

/* 
 * This is one of the dbus callbacks.
 * Caller requests creating a new @cgroup name of type @controller.
 * @name is taken to be relative to the caller's cgroup and may not
 * start with / or .. .
 */
int create_main (const char *controller, char *cgroup, struct ucred ucred, int *existed)
{
	char buf[1];
	DBusMessage *message = NULL;
	DBusMessageIter iter;
	int sv[2], ret = -1, optval = 1;
	dbus_uint32_t serial;;

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
		nih_error("Error creating socketpair: %s", strerror(errno));
		return -1;
	}
	if (setsockopt(sv[1], SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
		nih_error("setsockopt: %s", strerror(errno));
		goto out;
	}
	if (setsockopt(sv[0], SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
		nih_error("setsockopt: %s", strerror(errno));
		goto out;
	}

	message = dbus_message_new_method_call(dbus_bus_get_unique_name(server_conn),
			"/org/linuxcontainers/cgmanager",
			"org.linuxcontainers.cgmanager0_0", "CreateScm");

	dbus_message_iter_init_append(message, &iter);
        if (! dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &controller)) {
                nih_error_raise_no_memory ();
                goto out;
        }
        if (! dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &cgroup)) {
                nih_error_raise_no_memory ();
                goto out;
        }
	if (! dbus_message_iter_append_basic (&iter, DBUS_TYPE_UNIX_FD, &sv[1])) {
		nih_error_raise_no_memory ();
		goto out;
	}

	if (!dbus_connection_send(server_conn, message, &serial)) {
		nih_error("failed to send dbus message");
		goto out;
	}
	dbus_connection_flush(server_conn);
	if (message) {
		dbus_message_unref(message);
		message = NULL;
	}

	if (read(sv[0], buf, 1) != 1) {
		nih_error("Error getting reply from server over socketpair");
		goto out;
	}
	if (send_creds(sv[0], ucred)) {
		nih_error("Error sending pid over SCM_CREDENTIAL");
		goto out;
	}
	if (read(sv[0], buf, 1) == 1 && (*buf == '1' || *buf == '2'))
		ret = 0;
	*existed = *buf == '2' ? 1 : 0;
out:
	close(sv[0]);
	close(sv[1]);
	if (message)
		dbus_message_unref(message);
	return ret;
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
	nih_info (_("Client fd is: %d (pid=%d, uid=%d, gid=%d)"),
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
	struct ucred ucred;
	int fd, ret;
	socklen_t len;

	*existed = 0;
	if (message == NULL) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"message was null");
		return -1;
	}

	if (!dbus_connection_get_socket(message->connection, &fd)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
		                             "Could not get client socket.");
		return -1;
	}

	len = sizeof(struct ucred);
	NIH_MUST (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &ucred, &len) != -1);
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
 */
int chown_cgroup_main ( const char *controller, char *cgroup,
	struct ucred ucred, struct ucred vcred)
{
	char buf[1];
	DBusMessage *message = NULL;
	DBusMessageIter iter;
	int sv[2], ret = -1, optval = 1;
	dbus_uint32_t serial;;

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
		nih_error("Error creating socketpair: %s", strerror(errno));
		return -1;
	}
	if (setsockopt(sv[1], SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
		nih_error("setsockopt: %s", strerror(errno));
		goto out;
	}
	if (setsockopt(sv[0], SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
		nih_error("setsockopt: %s", strerror(errno));
		goto out;
	}

	message = dbus_message_new_method_call(dbus_bus_get_unique_name(server_conn),
			"/org/linuxcontainers/cgmanager",
			"org.linuxcontainers.cgmanager0_0", "chownCgroupScm");

	dbus_message_iter_init_append(message, &iter);
        if (! dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &controller)) {
                nih_error_raise_no_memory ();
                goto out;
        }
        if (! dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &cgroup)) {
                nih_error_raise_no_memory ();
                goto out;
        }
	if (! dbus_message_iter_append_basic (&iter, DBUS_TYPE_UNIX_FD, &sv[1])) {
		nih_error_raise_no_memory ();
		goto out;
	}

	if (!dbus_connection_send(server_conn, message, &serial)) {
		nih_error("failed to send dbus message");
		goto out;
	}
	dbus_connection_flush(server_conn);
	if (message) {
		dbus_message_unref(message);
		message = NULL;
	}

	if (read(sv[0], buf, 1) != 1) {
		nih_error("Error getting reply from server over socketpair");
		goto out;
	}
	if (send_creds(sv[0], ucred)) {
		nih_error("Error sending pid over SCM_CREDENTIAL");
		goto out;
	}
	if (read(sv[0], buf, 1) != 1) {
		nih_error("Error getting reply from server over socketpair");
		goto out;
	}
	if (send_creds(sv[0], vcred)) {
		nih_error("Error sending pid over SCM_CREDENTIAL");
		goto out;
	}
	if (read(sv[0], buf, 1) == 1 && *buf == '1')
		ret = 0;
out:
	close(sv[0]);
	close(sv[1]);
	if (message)
		dbus_message_unref(message);
	return ret;
}
void chown_cgroup_scm_reader (struct scm_sock_data *data,
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
	nih_info (_("Client fd is: %d (pid=%d, uid=%d, gid=%d)"),
		  data->fd, data->rcred.pid, data->rcred.uid, data->rcred.gid);
	nih_info (_("Victim is (uid=%d, gid=%d)"), vcred.uid, vcred.gid);

	*b = '0';
	if (chown_cgroup_main(data->controller, data->cgroup, data->rcred, vcred) == 0)
		*b = '1';
	if (write(data->fd, b, 1) < 0)
		nih_error("chownCgroupScm: Error writing final result to client");
out:
	nih_io_shutdown(io);
}
int cgmanager_chown_cgroup_scm (void *data, NihDBusMessage *message,
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
		(NihIoReader) chown_cgroup_scm_reader,
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
int cgmanager_chown_cgroup (void *data, NihDBusMessage *message,
		const char *controller, char *cgroup, int uid,
		int gid)
{
	struct ucred ucred, vcred;
	int fd, ret;
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
	vcred.pid = getpid();  // cgmanager ignores this
	vcred.uid = uid;
	vcred.gid = gid;
	if (!setns_pid_supported || !setns_user_supported) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"kernel too old, use chownCgroupScm");
		return -1;
	}
	if (!is_same_pidns(ucred.pid) || !is_same_userns(ucred.pid)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"requestor is in a different namespace from cgproxy");
		return -1;
	}
	ret = chown_cgroup_main(controller, cgroup, ucred, vcred);
	if (ret) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
				"invalid request");
		return -1;
	}
	return 0;
}

/* 
 * This is one of the dbus callbacks.
 * Caller requests the value of a particular cgroup file.
 * @controller is the controller, @req_cgroup the cgroup name, and @key the
 * file being queried (i.e. memory.usage_in_bytes).  @req_cgroup is relative
 * to the caller's cgroup, unless it begins with '/' or '..'.
 */
int get_value_main (void *parent, const char *controller, const char *req_cgroup,
		 const char *key, struct ucred ucred, char **value)
{
	char buf[1];
	DBusMessage *message = NULL;
	DBusMessageIter iter;
	int sv[2], ret = -1, optval = 1;
	dbus_uint32_t serial;;

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
		nih_error("Error creating socketpair: %s", strerror(errno));
		return -1;
	}
	if (setsockopt(sv[1], SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
		nih_error("setsockopt: %s", strerror(errno));
		goto out;
	}
	if (setsockopt(sv[0], SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
		nih_error("setsockopt: %s", strerror(errno));
		goto out;
	}

	message = dbus_message_new_method_call(dbus_bus_get_unique_name(server_conn),
			"/org/linuxcontainers/cgmanager",
			"org.linuxcontainers.cgmanager0_0", "getValueScm");

	dbus_message_iter_init_append(message, &iter);
        if (! dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &controller)) {
                nih_error_raise_no_memory ();
                goto out;
        }
        if (! dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &req_cgroup)) {
                nih_error_raise_no_memory ();
                goto out;
        }
        if (! dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &key)) {
                nih_error_raise_no_memory ();
                goto out;
        }
	if (! dbus_message_iter_append_basic (&iter, DBUS_TYPE_UNIX_FD, &sv[1])) {
		nih_error_raise_no_memory ();
		goto out;
	}

	if (!dbus_connection_send(server_conn, message, &serial)) {
		nih_error("failed to send dbus message");
		goto out;
	}
	dbus_connection_flush(server_conn);
	if (message) {
		dbus_message_unref(message);
		message = NULL;
	}

	if (read(sv[0], buf, 1) != 1) {
		nih_error("Error getting reply from server over socketpair");
		goto out;
	}
	if (send_creds(sv[0], ucred)) {
		nih_error("Error sending pid over SCM_CREDENTIAL");
		goto out;
	}
	char output[MAXPATHLEN];
	memset(output, 0, MAXPATHLEN);
	if (read(sv[0], output, MAXPATHLEN) <= 0)
		nih_error("Bad string from cgmanager");
	else {
		*value = nih_strdup(parent, output);
		ret = 0;
	}
out:
	close(sv[0]);
	close(sv[1]);
	if (message)
		dbus_message_unref(message);
	return ret;
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

	nih_info (_("Client fd is: %d (pid=%d, uid=%d, gid=%d)"),
		  data->fd, ucred.pid, ucred.uid, ucred.gid);

	if (!get_value_main(data, data->controller, data->cgroup, data->key, ucred, &output))
		ret = write(data->fd, output, strlen(output));
	else
		ret = write(data->fd, &ucred, 0);  // kick the client
	if (ret < 0)
		nih_error("getValueScm: Error writing final result to client");
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
	struct ucred ucred;
	int fd, ret;
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
	ret = get_value_main(message, controller, req_cgroup, key, ucred, value);
	if (ret) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
				"invalid request");
		return -1;
	}
	return 0;
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
	char buf[1];
	DBusMessage *message = NULL;
	DBusMessageIter iter;
	int sv[2], ret = -1, optval = 1;
	dbus_uint32_t serial;;

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
		nih_error("Error creating socketpair: %s", strerror(errno));
		return -1;
	}
	if (setsockopt(sv[1], SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
		nih_error("setsockopt: %s", strerror(errno));
		goto out;
	}
	if (setsockopt(sv[0], SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
		nih_error("setsockopt: %s", strerror(errno));
		goto out;
	}

	message = dbus_message_new_method_call(dbus_bus_get_unique_name(server_conn),
			"/org/linuxcontainers/cgmanager",
			"org.linuxcontainers.cgmanager0_0", "setValueScm");

	dbus_message_iter_init_append(message, &iter);
        if (! dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &controller)) {
                nih_error_raise_no_memory ();
                goto out;
        }
        if (! dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &req_cgroup)) {
                nih_error_raise_no_memory ();
                goto out;
        }
        if (! dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &key)) {
                nih_error_raise_no_memory ();
                goto out;
        }
        if (! dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &value)) {
                nih_error_raise_no_memory ();
                goto out;
        }
	if (! dbus_message_iter_append_basic (&iter, DBUS_TYPE_UNIX_FD, &sv[1])) {
		nih_error_raise_no_memory ();
		goto out;
	}

	if (!dbus_connection_send(server_conn, message, &serial)) {
		nih_error("failed to send dbus message");
		goto out;
	}
	dbus_connection_flush(server_conn);
	if (message) {
		dbus_message_unref(message);
		message = NULL;
	}

	if (read(sv[0], buf, 1) != 1) {
		nih_error("Error getting reply from server over socketpair");
		goto out;
	}
	if (send_creds(sv[0], ucred)) {
		nih_error("Error sending pid over SCM_CREDENTIAL");
		goto out;
	}
	if (read(sv[0], buf, 1) == 1 && *buf == '1')
		ret = 0;
out:
	close(sv[0]);
	close(sv[1]);
	if (message)
		dbus_message_unref(message);
	return ret;
}

void set_value_scm_reader (struct scm_sock_data *data,
		NihIo *io, const char *buf, size_t len)
{
	struct ucred ucred;
	int ret;
	char b[1];

	if (!get_nih_io_creds(io, &ucred)) {
		nih_error("failed to read ucred");
		goto out;
	}

	nih_info (_("Client fd is: %d (pid=%d, uid=%d, gid=%d)"),
		  data->fd, ucred.pid, ucred.uid, ucred.gid);

	ret = set_value_main(data->controller, data->cgroup, data->key, data->value, ucred);
	*b = ret == 0 ? '1' : '0';
	if (write(data->fd, b, 1) < 0)
		nih_error("setValueScm: Error writing final result to client");
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
	struct ucred ucred;
	int fd, ret;
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
	ret = set_value_main(controller, req_cgroup, key, value, ucred);
	if (ret)
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
				"invalid request");
	return ret;
}

/* 
 * This is one of the dbus callbacks.
 * Caller requests removing @cgroup name of type @controller.
 * @name is taken to be relative to the caller's cgroup and may not
 * start with / or .. .
 */
int remove_main (const char *controller, char *cgroup, struct ucred ucred, int recursive, int *existed)
{
	char buf[1];
	DBusMessage *message = NULL;
	DBusMessageIter iter;
	int sv[2], ret = -1, optval = 1;
	dbus_uint32_t serial;;

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
		nih_error("Error creating socketpair: %s", strerror(errno));
		return -1;
	}
	if (setsockopt(sv[1], SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
		nih_error("setsockopt: %s", strerror(errno));
		goto out;
	}
	if (setsockopt(sv[0], SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
		nih_error("setsockopt: %s", strerror(errno));
		goto out;
	}

	message = dbus_message_new_method_call(dbus_bus_get_unique_name(server_conn),
			"/org/linuxcontainers/cgmanager",
			"org.linuxcontainers.cgmanager0_0", "RemoveScm");

	dbus_message_iter_init_append(message, &iter);
        if (! dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &controller)) {
                nih_error_raise_no_memory ();
                goto out;
        }
        if (! dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &cgroup)) {
                nih_error_raise_no_memory ();
                goto out;
        }
        if (! dbus_message_iter_append_basic (&iter, DBUS_TYPE_INT32, &recursive)) {
                nih_error_raise_no_memory ();
                goto out;
        }
	if (! dbus_message_iter_append_basic (&iter, DBUS_TYPE_UNIX_FD, &sv[1])) {
		nih_error_raise_no_memory ();
		goto out;
	}

	if (!dbus_connection_send(server_conn, message, &serial)) {
		nih_error("failed to send dbus message");
		goto out;
	}
	dbus_connection_flush(server_conn);
	if (message) {
		dbus_message_unref(message);
		message = NULL;
	}

	if (read(sv[0], buf, 1) != 1) {
		nih_error("Error getting reply from server over socketpair");
		goto out;
	}
	if (send_creds(sv[0], ucred)) {
		nih_error("Error sending pid over SCM_CREDENTIAL");
		goto out;
	}
	if (read(sv[0], buf, 1) == 1 && (*buf == '1' || *buf == '2'))
		ret = 0;
	*existed = *buf == '2' ? 1 : 0;
out:
	close(sv[0]);
	close(sv[1]);
	if (message)
		dbus_message_unref(message);
	return ret;
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
	nih_info (_("Client fd is: %d (pid=%d, uid=%d, gid=%d)"),
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
	struct ucred ucred;
	int fd, ret;
	socklen_t len;

	*existed = 0;
	if (message == NULL) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"message was null");
		return -1;
	}

	if (!dbus_connection_get_socket(message->connection, &fd)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
		                             "Could not get client socket.");
		return -1;
	}

	len = sizeof(struct ucred);
	NIH_MUST (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &ucred, &len) != -1);
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
	char buf[1];
	DBusMessage *message = NULL;
	DBusMessageIter iter;
	int sv[2], ret = -1, optval = 1;
	dbus_uint32_t serial;;
	uid_t u; gid_t g;
	uint32_t nrpids;
	pid_t tmp;
	int i;

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
		nih_error("Error creating socketpair: %s", strerror(errno));
		return -1;
	}
	if (setsockopt(sv[1], SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
		nih_error("setsockopt: %s", strerror(errno));
		goto out;
	}
	if (setsockopt(sv[0], SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
		nih_error("setsockopt: %s", strerror(errno));
		goto out;
	}

	message = dbus_message_new_method_call(dbus_bus_get_unique_name(server_conn),
			"/org/linuxcontainers/cgmanager",
			"org.linuxcontainers.cgmanager0_0", "getTasksScm");

	dbus_message_iter_init_append(message, &iter);
        if (! dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &controller)) {
                nih_error_raise_no_memory ();
                goto out;
        }
        if (! dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &cgroup)) {
                nih_error_raise_no_memory ();
                goto out;
        }
	if (! dbus_message_iter_append_basic (&iter, DBUS_TYPE_UNIX_FD, &sv[1])) {
		nih_error_raise_no_memory ();
		goto out;
	}

	if (!dbus_connection_send(server_conn, message, &serial)) {
		nih_error("failed to send dbus message");
		goto out;
	}
	dbus_connection_flush(server_conn);
	if (message) {
		dbus_message_unref(message);
		message = NULL;
	}

	if (read(sv[0], buf, 1) != 1) {
		nih_error("Error getting reply from server over socketpair");
		goto out;
	}
	if (send_creds(sv[0], ucred)) {
		nih_error("Error sending pid over SCM_CREDENTIAL");
		goto out;
	}
	if (read(sv[0], &nrpids, sizeof(uint32_t)) != sizeof(uint32_t))
		goto out;
	if (nrpids == 0) {
		ret = 0;
		goto out;
	}

	*pids = nih_alloc(parent, nrpids * sizeof(uint32_t));
	for (i=0; i<nrpids; i++) {
		get_scm_creds_sync(sv[0], &u, &g, &tmp);
		if (tmp == -1) {
			nih_error("Failed getting pid from server");
			goto out;
		}
		(*pids)[i] = tmp;
	}
	ret = nrpids;
out:
	close(sv[0]);
	close(sv[1]);
	if (message)
		dbus_message_unref(message);
	return ret;
}

void get_tasks_scm_reader (struct scm_sock_data *data,
		NihIo *io, const char *buf, size_t len)
{
	struct ucred ucred, pcred;;
	int i, ret;
	int32_t *pids, nrpids;

	if (!get_nih_io_creds(io, &ucred)) {
		nih_error("failed to read ucred");
		goto out;
	}
	nih_info (_("getTasksScm: Client fd is: %d (pid=%d, uid=%d, gid=%d)"),
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

	nih_info (_("getTasks: Client fd is: %d (pid=%d, uid=%d, gid=%d)"),
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

int cgmanager_ping (void *data, NihDBusMessage *message, int junk)
{
	if (message == NULL) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"message was null");
		return -1;
	}

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

	nih_option_set_synopsis (_("Control group proxy"));
	nih_option_set_help (_("The cgroup manager proxy"));

	if (geteuid() != 0) {
		nih_error("Cgmanager proxy must be run as root");
		exit(1);
	}

	args = nih_option_parser (NULL, argc, argv, options, FALSE);
	if (! args)
		exit (1);

	if (setup_proxy() < 0) {
		nih_fatal ("Failed to set up as proxy");
		exit(1);
	}

	/* Setup the DBus server */
	server = nih_dbus_server ( CGMANAGER_DBUS_PATH, client_connect,
	                          client_disconnect);
	nih_assert (server != NULL);

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

	send_dummy_msg(server_conn);

	ret = nih_main_loop ();

	/* Destroy any PID file we may have created */
	if (daemonise) {
		nih_main_unlink_pidfile();
	}

	return ret;
}
