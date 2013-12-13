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

/*
 * Compute cgroup for @pid in @controller, appending @cgroup to
 * it.
 *
 * @dest is a pre-allocated MAXPATHLEN size array.
 */
static bool proxy_get_pid_cgroup(pid_t pid, const char *controller,
		const char *cgroup, char *dest)
{
	DBusMessage *message = NULL, *reply = NULL;
	DBusMessageIter iter;
	dbus_uint32_t serial;;
	int fd, optval = 1, retval = -1;

	if (!dest || !*dest || *dest == '.' || *dest == '/')
		return false;

	message = dbus_message_new_method_call(dbus_bus_get_unique_name(server_conn),
			"/org/linuxcontainers/cgmanager",
			"org.linuxcontainers.cgmanager0_0", "getPidCgroup");

	if (!dbus_connection_get_socket(server_conn, &fd)) {
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
        if (! dbus_message_iter_append_basic (&iter, DBUS_TYPE_INT32,
                                              &pid)) {
                nih_error_raise_no_memory ();
                return -1;
        }

	if (!dbus_connection_send(server_conn, message, &serial)) {
		nih_error("failed to send dbus message");
		return -1;
	}
	dbus_connection_flush(server_conn);

	if (send_pid(fd, pid)) {
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
	printf("%s\n", str_value);
	retval = 0;

out:
	if (message)
		dbus_message_unref(message);
	if (reply)
		dbus_message_unref(reply);

	return retval;
}

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
	pid_t target_pid;
	char rcgpath[MAXPATHLEN], vcgpath[MAXPATHLEN];

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

	/* Todo - we don't want to waste time waiting for scm_pid if none
	 * will be available. */
	target_pid = get_scm_pid(fd);

	if (target_pid == -1) {
		// non-root users can't send an SCM_CREDENTIAL for tasks
		// other than themselves.  For that case we accept a pid
		// as an integer only from our own pidns Non-root users
		// in another pidns will have to go through a root-owned
		// proxy in their own pidns.
		if (is_same_pidns((int)ucred.pid)) {
			nih_info("Using plain pid %d", (int)plain_pid);
			target_pid = plain_pid;
		}
	}
	if (target_pid == -1) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Could not retrieve pid from socket");
		return -1;
	}

	// Get r's current cgroup in rcgpath
	if (!proxy_get_pid_cgroup(ucred.pid, controller, "", rcgpath)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Could not determine the requestor cgroup");
		return -1;
	}

	// Get v's cgroup in vcgpath
	if (!proxy_get_pid_cgroup(target_pid, controller, "", vcgpath)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Could not determine the victim cgroup");
		return -1;
	}

	// Make sure v's cgroup is under r's
	int rlen = strlen(rcgpath);
	if (strncmp(rcgpath, vcgpath, rlen) != 0) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"v (%d)'s cgroup is not below r (%d)'s",
			(int)target_pid, (int)ucred.pid);
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
 * Caller requests moving a @pid to a particular cgroup identified
 * by the name (@cgroup) and controller type (@controller).
 */
int cgmanager_move_pid (void *data, NihDBusMessage *message,
			const char *controller, char *cgroup, int plain_pid,
			int *ok)
{
	nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
		"not yet implemented");
	return -1;
}

/* 
 * This is one of the dbus callbacks.
 * Caller requests creating a new @cgroup name of type @controller.
 * @name is taken to be relative to the caller's cgroup and may not
 * start with / or .. .
 */
int cgmanager_create (void *data, NihDBusMessage *message,
				 const char *controller, char *cgroup)
{
	nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
		"not yet implemented");
	return -1;
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
int cgmanager_chown_cgroup (void *data, NihDBusMessage *message,
			const char *controller, char *cgroup, int *ok)
{
	nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
		"not yet implemented");
	return -1;
}

/* 
 * This is one of the dbus callbacks.
 * Caller requests his own cgroup name for a given @controller.  The
 * name is returned as a nih_alloc'd string in @value with parent
 * @message, and is the full cgroup path.
 * This function may not be part of the final api, but is useful for
 * debugging now.
 * (The 'get-cgroup-bypid' callback will return a cgroup relative to
 * the caller's cgroup path)
 */
int cgmanager_get_my_cgroup (void *data, NihDBusMessage *message,
				 const char *controller, char **value)
{
	nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
		"not yet implemented");
	return -1;
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
int cgmanager_get_value (void *data, NihDBusMessage *message,
				 const char *controller, const char *req_cgroup,
		                 const char *key, char **value)

{
	nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
		"not yet implemented");
	return -1;
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
int cgmanager_set_value (void *data, NihDBusMessage *message,
				 const char *controller, const char *req_cgroup,
		                 const char *key, const char *value, int *ok)

{
	nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
		"not yet implemented");
	return -1;
}


static dbus_bool_t allow_user(DBusConnection *connection, unsigned long uid, void *data)
{
	return TRUE;
}

static int
client_connect (DBusServer *server, DBusConnection *conn)
{
	int optval = 1, fd;
	if (server == NULL || conn == NULL)
		return FALSE;

	dbus_connection_set_unix_user_function(conn, allow_user, NULL, NULL);
	dbus_connection_set_allow_anonymous(conn, TRUE);

	nih_info (_("Connection from private client"));

	NIH_MUST (nih_dbus_object_new (NULL, conn,
	          "/org/linuxcontainers/cgmanager",
	          cgmanager_interfaces, NULL));

	if (!dbus_connection_get_socket(conn, &fd)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
		                             "Could  not get client socket.");
		return -1;
	}

	/* need to do this before the client sends the msg */
	if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &optval,
			sizeof(optval)) == -1) {
		perror("setsockopt");
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"failed to set SO_PASSCRED socket option");
		return -1;
	}


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
