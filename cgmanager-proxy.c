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

#include "fs.h"
#include "access_checks.h"

#include "org.linuxcontainers.cgmanager.h"

#define PACKAGE_NAME "cgmanager"
#define PACKAGE_VERSION "0.0"
#define PACKAGE_BUGREPORT ""

#define UPPERFILE "/tmp/cgmanager"
#define LOWERFILE "/tmp/cgmanager.lower"
#define UPPERSOCK "unix:path=" UPPERFILE
#define LOWERSOCK "unix:path=" LOWERFILE

DBusConnection *server_conn;

int setup_proxy(void)
{
	bool exists_upper = false, exists_lower = false;

	/*
	 * If /tmp/cgmanager.lower exists,
	 *    if /tmp/cgmanager exists, then exit (proxy already running)
	 *    start up, connect to .lower
	 * else
	 *    if /tmp/cgmanager exists, move it to /tmp/cgmanager.lower
	 *    start up and connect to .lower
	 */
	server_conn = nih_dbus_connect(UPPERSOCK, NULL);
	if (server_conn) {
		exists_upper = true;
		dbus_connection_unref (server_conn);
	}
	server_conn = nih_dbus_connect(LOWERSOCK, NULL);
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
		//move /tmp/cgmanager to /tmp/cgmanager.lower
		if (creat(LOWERFILE, 0755) < 0 && errno != EEXIST) {
			nih_error("failed to create lower sock");
			return -1;
		}
		if (mount(UPPERFILE, LOWERFILE, "none", MS_MOVE, 0) < 0) {
			nih_error("unable to rename the socket");
			return -1;
		}
		if (unlink(UPPERFILE) < 0) {
			nih_error("unable to remove the old file");
			return -1;
		}
	}
	server_conn = nih_dbus_connect(LOWERSOCK, NULL);
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

int send_creds(int sock, struct ucred cred)
{
	struct msghdr msg = { 0 };
	struct iovec iov;
	struct cmsghdr *cmsg;
	char cmsgbuf[CMSG_SPACE(sizeof(cred))];
	char buf[1];
	buf[0] = 'p';

	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct ucred));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_CREDENTIALS;
	memcpy(CMSG_DATA(cmsg), &cred, sizeof(cred));

	msg.msg_name = NULL;
	msg.msg_namelen = 0;

	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if (sendmsg(sock, &msg, 0) < 0) {
		perror("sendmsg");
		return -1;
	}
	return 0;
}

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

/*
 * This is one of the dbus callbacks.
 * Caller requests the cgroup of @pid in a given @controller
 */
int get_pid_cgroup_main (const char *controller,
		struct ucred ucred, struct ucred vcred, char **output)
{
	char buf[1];
	DBusMessage *reply, *message;
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
		return -1;
	}
	dbus_connection_flush(server_conn);
	if (message) {
		dbus_message_unref(message);
		message = NULL;
	}

	if (read(sv[0], &buf, 1) != 1) {
		nih_error("Error getting reply from server over socketpair");
		goto out;
	}
	if (send_creds(sv[0], ucred)) {
		nih_error("Error sending pid over SCM_CREDENTIAL");
		goto out;
	}
	if (read(sv[0], &buf, 1) != 1) {
		nih_error("Error getting reply from server over socketpair");
		goto out;
	}
	if (send_creds(sv[0], vcred)) {
		nih_error("Error sending pid over SCM_CREDENTIAL");
		goto out;
	}
	while (!(reply = dbus_connection_pop_message(server_conn)))
		dbus_connection_read_write(server_conn, -1);
	if (dbus_message_get_reply_serial(reply) != serial) {
		nih_error("wrong serial on reply");
		goto out;
	}

	dbus_message_iter_init(reply, &iter);
	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING) {
		nih_error("Got bad reply type: %d", dbus_message_iter_get_arg_type(&iter));
		goto out;
	}
	char *str_value;
	dbus_message_iter_get_basic(&iter, &str_value);
	*output = strdup(str_value);
	ret = 0;
out:
	close(sv[0]);
	close(sv[1]);
	if (message)
		dbus_message_unref(message);
	if (reply)
		dbus_message_unref(reply);
	return ret;
}

int cgmanager_get_pid_cgroup_scm (void *data, NihDBusMessage *message,
			const char *controller, int sockfd, char **output)
{
	struct ucred ucred, vcred;

	if (message == NULL) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"message was null");
		close(sockfd);
		return -1;
	}

	get_scm_creds(sockfd, &ucred.uid, &ucred.gid, &ucred.pid);
	get_scm_creds(sockfd, &vcred.uid, &vcred.gid, &vcred.pid);
	close(sockfd);
	return get_pid_cgroup_main(controller, ucred, vcred, output);
}

int cgmanager_get_pid_cgroup (void *data, NihDBusMessage *message,
			const char *controller, int plain_pid, char **output)
{
	struct ucred ucred, vcred;
	int fd;
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
	return get_pid_cgroup_main(controller, ucred, vcred, output);
}

/*
 * This is one of the dbus callbacks.
 * Caller requests moving a @pid to a particular cgroup identified
 * by the name (@cgroup) and controller type (@controller).
 */
int move_pid_main (const char *controller, char *cgroup,
			struct ucred ucred, struct ucred vcred, int *ok)
{
	char buf[1];
	DBusMessage *reply, *message;
	DBusMessageIter iter;
	int sv[2], ret = -1, optval = 1;
	dbus_uint32_t serial;;

	*ok = -1;
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
		return -1;
	}
	dbus_connection_flush(server_conn);
	if (message) {
		dbus_message_unref(message);
		message = NULL;
	}

	if (read(sv[0], &buf, 1) != 1) {
		nih_error("Error getting reply from server over socketpair");
		goto out;
	}
	if (send_creds(sv[0], ucred)) {
		nih_error("Error sending pid over SCM_CREDENTIAL");
		goto out;
	}
	if (read(sv[0], &buf, 1) != 1) {
		nih_error("Error getting reply from server over socketpair");
		goto out;
	}
	if (send_creds(sv[0], vcred)) {
		nih_error("Error sending pid over SCM_CREDENTIAL");
		goto out;
	}
	while (!(reply = dbus_connection_pop_message(server_conn)))
		dbus_connection_read_write(server_conn, -1);
	if (dbus_message_get_reply_serial(reply) != serial) {
		nih_error("wrong serial on reply");
		goto out;
	}

	dbus_message_iter_init(reply, &iter);
	int t= dbus_message_iter_get_arg_type(&iter);
	short r;
	char *replystr;
	switch(t) {
	case DBUS_TYPE_INT16:
		dbus_message_iter_get_basic(&iter, &r);
		*ok = r;
		break;
	case DBUS_TYPE_INT32:
		dbus_message_iter_get_basic(&iter, ok);
		break;
	case DBUS_TYPE_STRING: // uh oh, must've failed
		dbus_message_iter_get_basic(&iter, &replystr);
		nih_error("Cgmanager returned error: %s", replystr);
		goto out;
	default:
		nih_error("Got bad reply type: %d", t);
		goto out;
	}
	ret = 0;
out:
	close(sv[0]);
	close(sv[1]);
	if (message)
		dbus_message_unref(message);
	if (reply)
		dbus_message_unref(reply);
	return ret;
}
int cgmanager_move_pid_scm (void *data, NihDBusMessage *message,
			const char *controller, char *cgroup, int sockfd,
			int *ok)
{
	struct ucred ucred, vcred;

	if (message == NULL) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"message was null");
		close(sockfd);
		return -1;
	}

	get_scm_creds(sockfd, &ucred.uid, &ucred.gid, &ucred.pid);
	get_scm_creds(sockfd, &vcred.uid, &vcred.gid, &vcred.pid);
	close(sockfd);

	return move_pid_main(controller, cgroup, ucred, vcred, ok);
}
int cgmanager_move_pid (void *data, NihDBusMessage *message,
			const char *controller, char *cgroup, int plain_pid,
			int *ok)
{
	struct ucred ucred, vcred;
	int fd;
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
	return move_pid_main(controller, cgroup, ucred, vcred, ok);
}

/* 
 * This is one of the dbus callbacks.
 * Caller requests creating a new @cgroup name of type @controller.
 * @name is taken to be relative to the caller's cgroup and may not
 * start with / or .. .
 */
int create_main (const char *controller, char *cgroup, struct ucred ucred)
{
	char buf[1];
	DBusMessage *reply, *message;
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
		return -1;
	}
	dbus_connection_flush(server_conn);
	if (message) {
		dbus_message_unref(message);
		message = NULL;
	}

	if (read(sv[0], &buf, 1) != 1) {
		nih_error("Error getting reply from server over socketpair");
		goto out;
	}
	if (send_creds(sv[0], ucred)) {
		nih_error("Error sending pid over SCM_CREDENTIAL");
		goto out;
	}
	while (!(reply = dbus_connection_pop_message(server_conn)))
		dbus_connection_read_write(server_conn, -1);
	if (dbus_message_get_reply_serial(reply) != serial) {
		nih_error("wrong serial on reply");
		goto out;
	}

	dbus_message_iter_init(reply, &iter);
	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING) {
		nih_error("Got bad reply type: %d", dbus_message_iter_get_arg_type(&iter));
		goto out;
	}
	int t= dbus_message_iter_get_arg_type(&iter);
	short r;
	int ok;
	char *replystr;
	switch(t) {
	case DBUS_TYPE_INT16:
		dbus_message_iter_get_basic(&iter, &r);
		nih_info("got back an int16, value %d", r);
		ok = r;
		break;
	case DBUS_TYPE_INT32:
		dbus_message_iter_get_basic(&iter, &ok);
		nih_info("got back an int32, value %d", ok);
		break;
	case DBUS_TYPE_STRING: // uh oh, must've failed
		dbus_message_iter_get_basic(&iter, &replystr);
		nih_error("Cgmanager returned error: %s", replystr);
		goto out;
	default:
		nih_error("Got bad reply type: %d", t);
		goto out;
	}
	if (ok == 0)
		ret = 0;
out:
	close(sv[0]);
	close(sv[1]);
	if (message)
		dbus_message_unref(message);
	if (reply)
		dbus_message_unref(reply);
	return ret;
}

int cgmanager_create_scm (void *data, NihDBusMessage *message,
		 const char *controller, char *cgroup, int sockfd, int *ok)
{
	struct ucred ucred;

	*ok = -1;
	if (message == NULL) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"message was null");
		close(sockfd);
		return -1;
	}

	get_scm_creds(sockfd, &ucred.uid, &ucred.gid, &ucred.pid);
	close(sockfd);
	if (create_main(controller, cgroup, ucred) == 0)
		*ok = 0;
	return 0;
}
int cgmanager_create (void *data, NihDBusMessage *message,
		 const char *controller, char *cgroup, int *ok)
{
	struct ucred ucred;
	int fd;
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
	if (create_main(controller, cgroup, ucred) == 0)
		*ok = 0;
	return 0;
}

/*
 * This is one of the dbus callbacks.
 * Caller requests chowning a cgroup @name in controller @cgroup to a
 * particular @uid.  The uid must be passed in as an scm_cred so the
 * kernel translates it for us.  @r must be root in its own user ns.
 *
 * On success, ok will be sent with value 1.  On failure, -1.
 */
int chown_cgroup_main ( const char *controller, char *cgroup,
	struct ucred ucred, struct ucred vcred, int *ok)
{
	char buf[1];
	DBusMessage *reply, *message;
	DBusMessageIter iter;
	int sv[2], ret = -1, optval = 1;
	dbus_uint32_t serial;;

	*ok = -1;
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
		return -1;
	}
	dbus_connection_flush(server_conn);
	if (message) {
		dbus_message_unref(message);
		message = NULL;
	}

	if (read(sv[0], &buf, 1) != 1) {
		nih_error("Error getting reply from server over socketpair");
		goto out;
	}
	if (send_creds(sv[0], ucred)) {
		nih_error("Error sending pid over SCM_CREDENTIAL");
		goto out;
	}
	if (read(sv[0], &buf, 1) != 1) {
		nih_error("Error getting reply from server over socketpair");
		goto out;
	}
	if (send_creds(sv[0], vcred)) {
		nih_error("Error sending pid over SCM_CREDENTIAL");
		goto out;
	}
	while (!(reply = dbus_connection_pop_message(server_conn)))
		dbus_connection_read_write(server_conn, -1);
	if (dbus_message_get_reply_serial(reply) != serial) {
		nih_error("wrong serial on reply");
		goto out;
	}

	dbus_message_iter_init(reply, &iter);
	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING) {
		nih_error("Got bad reply type: %d", dbus_message_iter_get_arg_type(&iter));
		goto out;
	}
	int t= dbus_message_iter_get_arg_type(&iter);
	short r;
	char *replystr;
	switch(t) {
	case DBUS_TYPE_INT16:
		dbus_message_iter_get_basic(&iter, &r);
		*ok = r;
		break;
	case DBUS_TYPE_INT32:
		dbus_message_iter_get_basic(&iter, ok);
		break;
	case DBUS_TYPE_STRING: // uh oh, must've failed
		dbus_message_iter_get_basic(&iter, &replystr);
		nih_error("Cgmanager returned error: %s", replystr);
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"%s", replystr);
		goto out;
	default:
		nih_error("Got bad reply type: %d", t);
		goto out;
	}
	if (*ok == 0)
		ret = 0;
out:
	close(sv[0]);
	close(sv[1]);
	if (message)
		dbus_message_unref(message);
	if (reply)
		dbus_message_unref(reply);
	return ret;
}
int cgmanager_chown_cgroup_scm (void *data, NihDBusMessage *message,
		const char *controller, char *cgroup, int sockfd, int *ok)
{
	struct ucred ucred, vcred;

	if (message == NULL) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"message was null");
		close(sockfd);
		return -1;
	}

	get_scm_creds(sockfd, &ucred.uid, &ucred.gid, &ucred.pid);
	get_scm_creds(sockfd, &vcred.uid, &vcred.gid, &vcred.pid);
	close(sockfd);
	return chown_cgroup_main(controller, cgroup, ucred, vcred, ok);
}
int cgmanager_chown_cgroup (void *data, NihDBusMessage *message,
		const char *controller, char *cgroup, int uid,
		int gid, int *ok)
{
	struct ucred ucred, vcred;
	int fd;
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
	return chown_cgroup_main(controller, cgroup, ucred, vcred, ok);
}

/* 
 * This is one of the dbus callbacks.
 * Caller requests the value of a particular cgroup file.
 * @controller is the controller, @req_cgroup the cgroup name, and @key the
 * file being queried (i.e. memory.usage_in_bytes).  @req_cgroup is relative
 * to the caller's cgroup, unless it begins with '/' or '..'.
 */
int get_value_main (const char *controller, const char *req_cgroup,
		 const char *key, struct ucred ucred, char **value)
{
	char buf[1];
	DBusMessage *reply, *message;
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
		return -1;
	}
	dbus_connection_flush(server_conn);
	if (message) {
		dbus_message_unref(message);
		message = NULL;
	}

	if (read(sv[0], &buf, 1) != 1) {
		nih_error("Error getting reply from server over socketpair");
		goto out;
	}
	if (send_creds(sv[0], ucred)) {
		nih_error("Error sending pid over SCM_CREDENTIAL");
		goto out;
	}
	while (!(reply = dbus_connection_pop_message(server_conn)))
		dbus_connection_read_write(server_conn, -1);
	if (dbus_message_get_reply_serial(reply) != serial) {
		nih_error("wrong serial on reply");
		goto out;
	}

	if (dbus_message_is_error(reply, DBUS_ERROR_INVALID_ARGS)) {
		nih_error("Server returned an error");
		goto out;
	}
	dbus_message_iter_init(reply, &iter);
	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING) {
		nih_error("Got bad reply type: %d", dbus_message_iter_get_arg_type(&iter));
		goto out;
	}
	char *str_value;
	dbus_message_iter_get_basic(&iter, &str_value);
	*value = strdup(str_value);
	ret = 0;
out:
	if (ret)
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Error received from server");
	close(sv[0]);
	close(sv[1]);
	if (message)
		dbus_message_unref(message);
	if (reply)
		dbus_message_unref(reply);
	return ret;
}

int cgmanager_get_value_scm (void *data, NihDBusMessage *message,
			 const char *controller, const char *req_cgroup,
			 const char *key, int sockfd, char **value)

{
	struct ucred ucred;

	if (message == NULL) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"message was null");
		close(sockfd);
		return -1;
	}

	get_scm_creds(sockfd, &ucred.uid, &ucred.gid, &ucred.pid);
	close(sockfd);
	return get_value_main(controller, req_cgroup, key, ucred, value);
}
int cgmanager_get_value (void *data, NihDBusMessage *message,
				 const char *controller, const char *req_cgroup,
		                 const char *key, char **value)

{
	struct ucred ucred;
	int fd;
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
	return get_value_main(controller, req_cgroup, key, ucred, value);
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
int set_value_main (const char *controller, const char *req_cgroup,
		 const char *key, const char *value, struct ucred ucred)
{
	char buf[1];
	DBusMessage *reply, *message;
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
		return -1;
	}
	dbus_connection_flush(server_conn);
	if (message) {
		dbus_message_unref(message);
		message = NULL;
	}

	if (read(sv[0], &buf, 1) != 1) {
		nih_error("Error getting reply from server over socketpair");
		goto out;
	}
	if (send_creds(sv[0], ucred)) {
		nih_error("Error sending pid over SCM_CREDENTIAL");
		goto out;
	}
	while (!(reply = dbus_connection_pop_message(server_conn)))
		dbus_connection_read_write(server_conn, -1);
	if (dbus_message_get_reply_serial(reply) != serial) {
		nih_error("wrong serial on reply");
		goto out;
	}

	dbus_message_iter_init(reply, &iter);
	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING) {
		nih_error("Got bad reply type: %d", dbus_message_iter_get_arg_type(&iter));
		goto out;
	}
	int t= dbus_message_iter_get_arg_type(&iter);
	short r;
	int ok;
	char *replystr;
	switch(t) {
	case DBUS_TYPE_INT16:
		dbus_message_iter_get_basic(&iter, &r);
		nih_info("got back an int16, value %d", r);
		ok = r;
		break;
	case DBUS_TYPE_INT32:
		dbus_message_iter_get_basic(&iter, &ok);
		nih_info("got back an int32, value %d", ok);
		break;
	case DBUS_TYPE_STRING: // uh oh, must've failed
		dbus_message_iter_get_basic(&iter, &replystr);
		nih_error("Cgmanager returned error: %s", replystr);
		goto out;
	default:
		nih_error("Got bad reply type: %d", t);
		goto out;
	}
	if (ok == 0)
		ret = 0;
out:
	close(sv[0]);
	close(sv[1]);
	if (message)
		dbus_message_unref(message);
	if (reply)
		dbus_message_unref(reply);
	return ret;
}

int cgmanager_set_value_scm (void *data, NihDBusMessage *message,
		 const char *controller, const char *req_cgroup,
		 const char *key, const char *value, int sockfd, int *ok)

{
	struct ucred ucred;

	*ok = -1;
	if (message == NULL) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"message was null");
		close(sockfd);
		return -1;
	}

	get_scm_creds(sockfd, &ucred.uid, &ucred.gid, &ucred.pid);
	close(sockfd);
	if (set_value_main(controller, req_cgroup, key, value, ucred) == 0)
		*ok = 0;
	return 0;
}
int cgmanager_set_value (void *data, NihDBusMessage *message,
		 const char *controller, const char *req_cgroup,
		 const char *key, const char *value, int *ok)

{
	struct ucred ucred;
	int fd;
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
	if (set_value_main(controller, req_cgroup, key, value, ucred) == 0)
		*ok = 0;
	return 0;
}

int cgmanager_ping (void *data, NihDBusMessage *message, const char *controller)
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
	server = nih_dbus_server ( UPPERSOCK, client_connect,
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
