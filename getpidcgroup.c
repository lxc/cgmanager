/* getpidcgroup
 *
 * Copyright © 2013 Serge Hallyn
 * Author: Serge Hallyn <serge.hallyn@ubuntu.com>
 *
 * This is only for testing purposes - we really want to update dbus-send
 * to accept a 'pid' arg type which sends the pid as a scm_credential.
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
#include <sys/types.h>
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
#include <nih-dbus/dbus_proxy.h>
#include <nih-dbus/dbus_error.h>

#include <sys/socket.h>

#define PACKAGE_NAME "cgmanager"
#define PACKAGE_VERSION "0.0"
#define PACKAGE_BUGREPORT ""

static int pid = -1;
static const char *controller;

typedef int (*NihOptionSetter) (NihOption *option, const char *arg);

int set_pid(NihOption *option, const char *arg)
{
	unsigned long int p;
	errno = 0;
	p = strtoul(arg, NULL, 10);
	nih_assert(errno == 0);
	nih_assert(p < INT_MAX);
	if (!p)
		pid = getpid();
	else
		pid = (int)p;
	return 0;
}

int set_controller(NihOption *option, const char *arg)
{
	controller = arg;
	return 0;
}

/**
 * options:
 *
 * Command-line options accepted by this program.
 **/
static NihOption options[] = {
	{ 'c', "controller", N_("Controller for which to act"),
	  NULL, "CONTROLLER", NULL, set_controller },
	{ 'p', "pid", N_("Pid to move"),
	  NULL, "PID", NULL, set_pid },

	NIH_OPTION_LAST
};

int send_pid(int sock, int pid)
{
	struct msghdr msg = { 0 };
	struct iovec iov;
	struct cmsghdr *cmsg;
	struct ucred cred = {
		.pid = pid,
		.uid = geteuid(),
		.gid = getegid(),
	};
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

static void usage(char *me) {
	fprintf(stderr, "Usage: %s -c controller -p pid\n", me);
	exit(1);
}

int
main (int   argc,
      char *argv[])
{
	char **             args;
	DBusConnection *    conn;
	int fd, optval = 1, exitval = 1;
	DBusMessage *message = NULL, *reply = NULL;
	DBusMessageIter iter;
	dbus_uint32_t serial;;
	int sv[2] = {-1, -1};
	char buf[1];

	nih_main_init (argv[0]);

	nih_option_set_synopsis (_("Control group client"));

	args = nih_option_parser (NULL, argc, argv, options, FALSE);
	if (! args)
		exit (1);

	if (!controller)
		usage(argv[0]);

	if (pid == -1)
		pid = getpid();

	if (geteuid() != 0) {
		nih_error("%s must be run as root", argv[0]);
		exit(1);
	}
	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
		nih_error("Error creating socketpair: %s", strerror(errno));
		exit(1);
	}
	if (setsockopt(sv[1], SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
		perror("setsockopt");
		exit(1);
	}
	if (setsockopt(sv[0], SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
		perror("setsockopt");
		exit(1);
	}

	conn = nih_dbus_connect("unix:path=/tmp/cgmanager", NULL);
	nih_assert (conn != NULL);

	message = dbus_message_new_method_call(dbus_bus_get_unique_name(conn),
			"/org/linuxcontainers/cgmanager",
			"org.linuxcontainers.cgmanager0_0", "getPidCgroupScm");

	if (!dbus_connection_get_socket(conn, &fd)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
					"Could not get socket");
		return -1;
	}
	if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
		perror("setsockopt");
		return -1;
	}

	dbus_message_iter_init_append(message, &iter);
        if (! dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING,
                                              &controller)) {
                nih_error_raise_no_memory ();
                return -1;
        }
	dbus_message_iter_init_append(message, &iter);
	if (! dbus_message_iter_append_basic (&iter, DBUS_TYPE_UNIX_FD,
					      &sv[1])) {
		nih_error_raise_no_memory ();
		return -1;
	}

	if (!dbus_connection_send(conn, message, &serial)) {
		nih_error("failed to send dbus message");
		return -1;
	}
	dbus_connection_flush(conn);

	if (read(sv[0], &buf, 1) != 1) {
		nih_error("Error getting reply from server over socketpair");
		goto out;
	}
	if (send_pid(sv[0], pid)) {
		nih_error("Error sending pid over SCM_CREDENTIAL");
		goto out;
	}
	close(sv[0]);
	close(sv[1]);

	while (!(reply = dbus_connection_pop_message(conn)))
		dbus_connection_read_write(conn, -1);
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
	printf("%s\n", str_value);
	exitval = 0;

out:
	if (message)
		dbus_message_unref(message);
	if (reply)
		dbus_message_unref(reply);
	dbus_connection_unref (conn);
	exit(exitval);
}
