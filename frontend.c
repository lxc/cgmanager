/* frontend.c: definitions of the dbus and scm-enhanced dbus
 *             frontend routines.
 *
 * Copyright © 2013 Stephane Graber
 * Author: Stephane Graber <stgraber@ubuntu.com>
 * Copyright © 2014 Canonical Group Limited
 * Author: Serge Hallyn <serge.hallyn@ubuntu.com>
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

#define __frontend_c
#include <frontend.h>

int daemonise = FALSE;
int sigstop = FALSE;
bool setns_pid_supported = false;
unsigned long mypidns;
bool setns_user_supported = false;
unsigned long myuserns;

bool sane_cgroup(const char *cgroup)
{
	if (!cgroup)
		return false;
	if (strstr(cgroup, ".."))
		return false;
	return true;
}

/* This function is done at the start of every Scm-enhanced transaction */
static struct scm_sock_data *alloc_scm_sock_data(NihDBusMessage *message,
		int fd, enum req_type t)
{
	struct scm_sock_data *d;
	int optval = 1, dbusfd;
	socklen_t len;

	if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
				"Failed to set passcred: %s", strerror(errno));
		return NULL;
	}
	d = NIH_MUST( nih_alloc(NULL, sizeof(*d)) );
	memset(d, 0, sizeof(*d));
	d->fd = fd;
	d->type = t;

	if (!dbus_connection_get_socket(message->connection, &dbusfd)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
					     "Could not get client socket.");
		return NULL;
	}

	/* Read the proxy's credentials from dbus fd */
	len = sizeof(struct ucred);
	if (getsockopt(dbusfd, SOL_SOCKET, SO_PEERCRED, &d->pcred, &len) < 0) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
					     "Could not get peer cred: %s",
					     strerror(errno));
		return NULL;
	}

	return d;
}

/*
 * All Scm-enhanced transactions take at least one SCM cred,
 * the requestor's.  Some require a second SCM cred to identify
 * a pid or uid/gid:
 */
static bool need_two_creds(enum req_type t)
{
	switch (t) {
	case REQ_TYPE_GET_PID:
	case REQ_TYPE_GET_PID_ABS:
	case REQ_TYPE_MOVE_PID:
	case REQ_TYPE_MOVE_PID_ABS:
	case REQ_TYPE_CHOWN:
		return true;
	default:
		return false;
	}
}

static void scm_sock_error_handler (void *data, NihIo *io)
{
	struct scm_sock_data *d = data;
	NihError *error = nih_error_get ();
	nih_free(error);
	d->fd = -1;
}

static void scm_sock_close (struct scm_sock_data *data, NihIo *io)
{
	nih_assert (data);
	nih_assert (io);

	nih_free (io);

	// Only delete data struct after io, because freeing io may call methods
	// like error_handler that use this data struct.
	if (data->fd != -1)
		close (data->fd);
	nih_free (data);
}

/*
 * Write a char over the socket to tell the client we're ready for
 * the next SCM credential.
 */
static bool kick_fd_client(int fd)
{
	char buf = '1';
	if (write(fd, &buf, 1) != 1) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed to start write on scm fd: %s", strerror(errno));
		return false;
	}
	return true;
}

/*
 * Called when an scm credential has been received.  If this was
 * the first of two expected creds, then kick the client again
 * and wait (async) for the next credential.  Otherwise, call
 * the appropriate completion function to finish the transaction.
 */
static void sock_scm_reader(struct scm_sock_data *data,
			NihIo *io, const char *buf, size_t len)
{
	struct ucred ucred;

	if (!get_nih_io_creds(data, io, &ucred)) {
		nih_error("failed to read ucred");
		nih_io_shutdown(io);
		return;
	}
	if (data->step == 0) {
		memcpy(&data->rcred, &ucred, sizeof(struct ucred));
		if (need_two_creds(data->type)) {
			data->step = 1;
			if (!kick_fd_client(data->fd))
				nih_io_shutdown(io);
			return;
		}
	} else
		memcpy(&data->vcred, &ucred, sizeof(struct ucred));

	switch (data->type) {
	case REQ_TYPE_GET_PID: get_pid_scm_complete(data); break;
	case REQ_TYPE_GET_PID_ABS: get_pid_abs_scm_complete(data); break;
	case REQ_TYPE_MOVE_PID: move_pid_scm_complete(data); break;
	case REQ_TYPE_MOVE_PID_ABS: move_pid_abs_scm_complete(data); break;
	case REQ_TYPE_CREATE: create_scm_complete(data); break;
	case REQ_TYPE_CHOWN: chown_scm_complete(data); break;
	case REQ_TYPE_CHMOD: chmod_scm_complete(data); break;
	case REQ_TYPE_GET_VALUE: get_value_complete(data); break;
	case REQ_TYPE_SET_VALUE: set_value_complete(data); break;
	case REQ_TYPE_REMOVE: remove_scm_complete(data); break;
	case REQ_TYPE_GET_TASKS: get_tasks_scm_complete(data); break;
	case REQ_TYPE_LIST_CHILDREN: list_children_scm_complete(data); break;
	case REQ_TYPE_REMOVE_ON_EMPTY: remove_on_empty_scm_complete(data); break;
	case REQ_TYPE_PRUNE: prune_scm_complete(data); break;
	case REQ_TYPE_GET_TASKS_RECURSIVE: get_tasks_recursive_scm_complete(data); break;
	case REQ_TYPE_LISTKEYS: list_keys_scm_complete(data); break;
	default:
		nih_fatal("%s: bad req_type %d", __func__, data->type);
		exit(1);
	}
	nih_io_shutdown(io);
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

void get_pid_scm_complete(struct scm_sock_data *data)
{
	// output will be nih_alloced with data as parent, and therefore
	// freed when data is freed.
	char *output = NULL;
	int ret;

	ret = get_pid_cgroup_main(data, data->controller, data->pcred,
			data->rcred, data->vcred, &output);
	if (ret == 0)
		ret = write(data->fd, output, strlen(output)+1);
	else
		// Let the client know it failed
		ret = write(data->fd, &data->rcred, 0);
	if (ret < 0)
		nih_error("GetPidCgroupScm: Error writing final result to client: %s",
			strerror(errno));
}

/*
 * This is one of the dbus callbacks.
 * Caller requests the cgroup of @pid in a given @controller
 */
int cgmanager_get_pid_cgroup_scm (void *data, NihDBusMessage *message,
			const char *controller, int sockfd)
{
	struct scm_sock_data *d;

	d = alloc_scm_sock_data(message, sockfd, REQ_TYPE_GET_PID);
	if (!d)
		return -1;
	d->controller = NIH_MUST( nih_strdup(d, controller) );

	if (!nih_io_reopen(NULL, sockfd, NIH_IO_MESSAGE,
				(NihIoReader) sock_scm_reader,
				(NihIoCloseHandler) scm_sock_close,
				scm_sock_error_handler, d)) {
		NihError *error = nih_error_steal ();
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed queue scm message: %s", error->message);
		nih_free(error);
		return -1;
	}

	if (!kick_fd_client(sockfd))
		return -1;
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
	struct ucred rcred, vcred;
	socklen_t len;

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
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &rcred, &len) < 0) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
					     "Could not get peer cred: %s",
					     strerror(errno));
		return -1;
	}

	nih_info (_("GetPidCgroup: Client fd is: %d (pid=%d, uid=%u, gid=%u)"),
			fd, rcred.pid, rcred.uid, rcred.gid);

	/*
	 * getpidcgroup results cannot make sense as the pid is not
	 * translated.  Note that on an old enough kernel we cannot detect
	 * this situation.  In that case we allow it - it will confuse the
	 * caller, but cause no harm
	 */
	if (!is_same_pidns(rcred.pid)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
				"GetPidCgroup called from non-init namespace");
		return -1;
	}
	vcred.uid = 0;
	vcred.gid = 0;
	vcred.pid = plain_pid;
	ret = get_pid_cgroup_main(message, controller, rcred, rcred, vcred, output);
	if (ret) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
				"invalid request");
		return -1;
	}
	return 0;
}

void get_pid_abs_scm_complete(struct scm_sock_data *data)
{
	// output will be nih_alloced with data as parent, and therefore
	// freed when data is freed.
	char *output = NULL;
	int ret;

	ret = get_pid_cgroup_abs_main(data, data->controller, data->pcred,
			data->rcred, data->vcred, &output);
	if (ret == 0)
		ret = write(data->fd, output, strlen(output)+1);
	else
		// Let the client know it failed
		ret = write(data->fd, &data->rcred, 0);
	if (ret < 0)
		nih_error("GetPidCgroupAbsScm: Error writing final result to client: %s",
			strerror(errno));
}

/*
 * This is one of the dbus callbacks.
 * Caller requests the cgroup of @pid in a given @controller, relative
 * to the proxy's
 */
int cgmanager_get_pid_cgroup_abs_scm (void *data, NihDBusMessage *message,
			const char *controller, int sockfd)
{
	struct scm_sock_data *d;

	d = alloc_scm_sock_data(message, sockfd, REQ_TYPE_GET_PID_ABS);
	if (!d)
		return -1;
	d->controller = NIH_MUST( nih_strdup(d, controller) );

	if (!nih_io_reopen(NULL, sockfd, NIH_IO_MESSAGE,
				(NihIoReader) sock_scm_reader,
				(NihIoCloseHandler) scm_sock_close,
				scm_sock_error_handler, d)) {
		NihError *error = nih_error_steal ();
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed queue scm message: %s", error->message);
		nih_free(error);
		return -1;
	}

	if (!kick_fd_client(sockfd))
		return -1;
	return 0;
}

/* GetPidCgroup */
/*
 * This is one of the dbus callbacks.
 * Caller requests the cgroup of @pid in a given @controller relative
 * to the proxy's
 */
int cgmanager_get_pid_cgroup_abs (void *data, NihDBusMessage *message,
			const char *controller, int plain_pid, char **output)
{
	int fd = 0, ret;
	struct ucred rcred, vcred;
	socklen_t len;

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
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &rcred, &len) < 0) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
					     "Could not get peer cred: %s",
					     strerror(errno));
		return -1;
	}

	nih_info (_("GetPidCgroupAbs: Client fd is: %d (pid=%d, uid=%u, gid=%u)"),
			fd, rcred.pid, rcred.uid, rcred.gid);

	/*
	 * getpidcgroup results cannot make sense as the pid is not
	 * translated.  Note that on an old enough kernel we cannot detect
	 * this situation.  In that case we allow it - it will confuse the
	 * caller, but cause no harm
	 */
	if (!is_same_pidns(rcred.pid)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
				"GetPidCgroupAbs called from non-init namespace");
		return -1;
	}
	vcred.uid = 0;
	vcred.gid = 0;
	vcred.pid = plain_pid;

#ifdef CGMANAGER
	/*
	 * A plain dbus request to escape cgroup root was made by a root
	 * owned task in cgmanager's namespace.  We will send ourselves as the
	 * proxy.
	 */
	struct ucred mycred = {
		.pid = getpid(),
		.uid = getuid(),
		.gid = getgid()
	};
#else
	/*
	 * This is the !CGMANAGER case.  We are in the proxy.  We don't
	 * support chained proxying anyway, so it is simple - the requestor
	 * is the proxy at this point;  then we will proxy the call on to
	 * the cgmanager
	 */
#define mycred rcred
#endif

	ret = get_pid_cgroup_abs_main(message, controller, mycred, rcred, vcred, output);
	if (ret) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
				"invalid request");
		return -1;
	}
	return 0;
}

void move_pid_scm_complete(struct scm_sock_data *data)
{
	char b = '0';

	if (move_pid_main(data->controller, data->cgroup, data->pcred,
				data->rcred, data->vcred) == 0)
		b = '1';
	if (write(data->fd, &b, 1) < 0)
		nih_error("MovePidScm: Error writing final result to client");
}

int cgmanager_move_pid_scm (void *data, NihDBusMessage *message,
			const char *controller, const char *cgroup,
			int sockfd)
{
	struct scm_sock_data *d;

	d = alloc_scm_sock_data(message, sockfd, REQ_TYPE_MOVE_PID);
	if (!d)
		return -1;
	d->controller = NIH_MUST( nih_strdup(d, controller) );
	d->cgroup = NIH_MUST( nih_strdup(d, cgroup) );

	if (!nih_io_reopen(NULL, sockfd, NIH_IO_MESSAGE,
				(NihIoReader) sock_scm_reader,
				(NihIoCloseHandler) scm_sock_close,
				scm_sock_error_handler, d)) {
		NihError *error = nih_error_steal ();
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed queue scm message: %s", error->message);
		nih_free(error);
		return -1;
	}
	if (!kick_fd_client(sockfd))
		return -1;
	return 0;
}

/*
 * This is one of the dbus callbacks.
 * Caller requests moving a @pid to a particular cgroup identified
 * by the name (@cgroup) and controller type (@controller).
 */
int cgmanager_move_pid (void *data, NihDBusMessage *message,
			const char *controller, const char *cgroup, int plain_pid)
{
	int fd = 0, ret;
	struct ucred rcred, vcred;
	socklen_t len;

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
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &rcred, &len) < 0) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
					     "Could not get peer cred: %s",
					     strerror(errno));
		return -1;
	}

	nih_info (_("MovePid: Client fd is: %d (pid=%d, uid=%u, gid=%u)"),
			fd, rcred.pid, rcred.uid, rcred.gid);

	/* If task is in a different namespace, require a proxy */
	if (!is_same_pidns(rcred.pid)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			     "Escape request from different namespace requires a proxy");
		return -1;
	}

	vcred.uid = 0;
	vcred.gid = 0;
	vcred.pid = plain_pid;
	ret = move_pid_main(controller, cgroup, rcred, rcred, vcred);
	if (ret)
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
					     "invalid request");
	return ret;
}

void move_pid_abs_scm_complete(struct scm_sock_data *data)
{
	char b = '0';

	if (move_pid_abs_main(data->controller, data->cgroup, data->pcred,
				data->rcred, data->vcred) == 0)
		b = '1';
	if (write(data->fd, &b, 1) < 0)
		nih_error("MovePidScm: Error writing final result to client");
}

int cgmanager_move_pid_abs_scm (void *data, NihDBusMessage *message,
			const char *controller, const char *cgroup,
			int sockfd)
{
	struct scm_sock_data *d;

	d = alloc_scm_sock_data(message, sockfd, REQ_TYPE_MOVE_PID_ABS);
	if (!d)
		return -1;
	d->controller = NIH_MUST( nih_strdup(d, controller) );
	d->cgroup = NIH_MUST( nih_strdup(d, cgroup) );

	if (!nih_io_reopen(NULL, sockfd, NIH_IO_MESSAGE,
				(NihIoReader) sock_scm_reader,
				(NihIoCloseHandler) scm_sock_close,
				scm_sock_error_handler, d)) {
		NihError *error = nih_error_steal ();
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed queue scm message: %s", error->message);
		nih_free(error);
		return -1;
	}
	if (!kick_fd_client(sockfd))
		return -1;
	return 0;
}

int cgmanager_move_pid_abs (void *data, NihDBusMessage *message,
			const char *controller, const char *cgroup, int plain_pid)
{
	int fd = 0, ret;
	struct ucred rcred, vcred;
	socklen_t len;

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
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &rcred, &len) < 0) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
					     "Could not get peer cred: %s",
					     strerror(errno));
		return -1;
	}

	nih_info (_("MovePid: Client fd is: %d (pid=%d, uid=%u, gid=%u)"),
			fd, rcred.pid, rcred.uid, rcred.gid);

	vcred.uid = 0;
	vcred.gid = 0;
	vcred.pid = plain_pid;

#ifdef CGMANAGER
	/*
	 * On an older kernel, require a proxy
	 */
	if (!setns_pid_supported) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
					     "A proxy is required");
		return -1;
	}
#endif

	/* If task is in a different namespace, require a proxy */
	if (!is_same_pidns(rcred.pid)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			     "Escape request from different namespace requires a proxy");
		return -1;
	}

#ifdef CGMANAGER
	/*
	 * A plain dbus request to escape cgroup root was made by a root
	 * owned task in cgmanager's namespace.  We will send ourselves as the
	 * proxy.
	 */
	struct ucred mycred = {
		.pid = getpid(),
		.uid = getuid(),
		.gid = getgid()
	};
#else
	/*
	 * This is the !CGMANAGER case.  We are in the proxy.  We don't
	 * support chained proxying anyway, so it is simple - the requestor
	 * is the proxy at this point;  then we will proxy the call on to
	 * the cgmanager
	 */
#define mycred rcred
#endif
	ret = move_pid_abs_main(controller, cgroup, mycred, rcred, vcred);
	if (ret)
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
					     "invalid request");
	return ret;
}

void create_scm_complete(struct scm_sock_data *data)
{
	char b = '0';
	int32_t existed;

	if (create_main(data->controller, data->cgroup, data->pcred,
				data->rcred, &existed) == 0)
		b = existed == 1 ? '2' : '1';
	if (write(data->fd, &b, 1) < 0)
		nih_error("createScm: Error writing final result to client");
}

int cgmanager_create_scm (void *data, NihDBusMessage *message,
		 const char *controller, const char *cgroup, int sockfd)
{
	struct scm_sock_data *d;

	d = alloc_scm_sock_data(message, sockfd, REQ_TYPE_CREATE);
	if (!d)
		return -1;
	d->controller = NIH_MUST( nih_strdup(d, controller) );
	d->cgroup = NIH_MUST( nih_strdup(d, cgroup) );

	if (!nih_io_reopen(NULL, sockfd, NIH_IO_MESSAGE,
				(NihIoReader) sock_scm_reader,
				(NihIoCloseHandler) scm_sock_close,
				scm_sock_error_handler, d)) {
		NihError *error = nih_error_steal ();
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed queue scm message: %s", error->message);
		nih_free(error);
		return -1;
	}
	if (!kick_fd_client(sockfd))
		return -1;
	return 0;
}

/*
 * This is one of the dbus callbacks.
 * Caller requests creating a new @cgroup name of type @controller.
 * @name is taken to be relative to the caller's cgroup and may not
 * start with / or .. .
 */
int cgmanager_create (void *data, NihDBusMessage *message,
			 const char *controller, const char *cgroup, int32_t *existed)
{
	int fd = 0, ret;
	struct ucred rcred;
	socklen_t len;

	*existed = -1;
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
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &rcred, &len) < 0) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
					     "Could not get peer cred: %s",
					     strerror(errno));
		return -1;
	}

	nih_info (_("Create: Client fd is: %d (pid=%d, uid=%u, gid=%u)"),
			fd, rcred.pid, rcred.uid, rcred.gid);

	ret = create_main(controller, cgroup, rcred, rcred, existed);
	if (ret)
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
				"invalid request");
	nih_info(_("%s: returning %d; existed is %d"), __func__, ret, *existed);
	return ret;
}

void chown_scm_complete(struct scm_sock_data *data)
{
	char b = '0';

	if (chown_main(data->controller, data->cgroup, data->pcred,
				data->rcred, data->vcred) == 0)
		b = '1';
	if (write(data->fd, &b, 1) < 0)
		nih_error("ChownScm: Error writing final result to client");
}

int cgmanager_chown_scm (void *data, NihDBusMessage *message,
			const char *controller, const char *cgroup, int sockfd)
{
	struct scm_sock_data *d;

	d = alloc_scm_sock_data(message, sockfd, REQ_TYPE_CHOWN);
	if (!d)
		return -1;
	d->controller = NIH_MUST( nih_strdup(d, controller) );
	d->cgroup = NIH_MUST( nih_strdup(d, cgroup) );

	if (!nih_io_reopen(NULL, sockfd, NIH_IO_MESSAGE,
				(NihIoReader)  sock_scm_reader,
				(NihIoCloseHandler) scm_sock_close,
				scm_sock_error_handler, d)) {
		NihError *error = nih_error_steal ();
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed queue scm message: %s", error->message);
		nih_free(error);
		return -1;
	}
	if (!kick_fd_client(sockfd))
		return -1;
	return 0;
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
int cgmanager_chown (void *data, NihDBusMessage *message,
			const char *controller, const char *cgroup, int uid, int gid)
{
	int fd = 0, ret;
	struct ucred rcred, vcred;
	socklen_t len;

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
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &rcred, &len) < 0) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
					     "Could not get peer cred: %s",
					     strerror(errno));
		return -1;
	}

	nih_info (_("Chown: Client fd is: %d (pid=%d, uid=%u, gid=%u)"),
			fd, rcred.pid, rcred.uid, rcred.gid);

	/*
	 * If chown is called from a different user namespace, then the
	 * results cannot make sense.  Note that on an old enough kernel
	 * we cannot detect this.  However, in that case the caller will
	 * not have privilege so will simply get a confusing -EPERM.  In
	 * other words, we are doing this as a courtesy when possible
	 */
	if (!is_same_userns(rcred.pid)) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
				"chown called from different user namespace");
		return -1;
	}

	vcred.pid = getpid(); // cgmanager ignores this
	vcred.uid = uid;
	vcred.gid = gid;

	ret = chown_main(controller, cgroup, rcred, rcred, vcred);
	if (ret)
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
					     "invalid request");
	return ret;
}

void chmod_scm_complete(struct scm_sock_data *data)
{
	char b = '0';

	if (chmod_main(data->controller, data->cgroup, data->file,
				data->pcred, data->rcred, data->mode) == 0)
		b = '1';
	if (write(data->fd, &b, 1) < 0)
		nih_error("ChownScm: Error writing final result to client");
}

int cgmanager_chmod_scm (void *data, NihDBusMessage *message,
			const char *controller, const char *cgroup,
			const char *file, int mode, int sockfd)
{
	struct scm_sock_data *d;

	d = alloc_scm_sock_data(message, sockfd, REQ_TYPE_CHMOD);
	if (!d)
		return -1;
	d->controller = NIH_MUST( nih_strdup(d, controller) );
	d->cgroup = NIH_MUST( nih_strdup(d, cgroup) );
	d->mode = mode;
	d->file = NIH_MUST( nih_strdup(d, file) );

	if (!nih_io_reopen(NULL, sockfd, NIH_IO_MESSAGE,
				(NihIoReader)  sock_scm_reader,
				(NihIoCloseHandler) scm_sock_close,
				scm_sock_error_handler, d)) {
		NihError *error = nih_error_steal ();
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed queue scm message: %s", error->message);
		nih_free(error);
		return -1;
	}
	if (!kick_fd_client(sockfd))
		return -1;
	return 0;
}

/*
 * This is one of the dbus callbacks.  Caller requests chmoding a file @path in
 * cgroup @name in controller @cgroup to a new @mode.  
 */
int cgmanager_chmod (void *data, NihDBusMessage *message,
			const char *controller, const char *cgroup,
			const char *file, int mode)
{
	int fd = 0, ret;
	struct ucred rcred;
	socklen_t len;

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
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &rcred, &len) < 0) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
					     "Could not get peer cred: %s",
					     strerror(errno));
		return -1;
	}

	nih_info (_("Chown: Client fd is: %d (pid=%d, uid=%u, gid=%u)"),
			fd, rcred.pid, rcred.uid, rcred.gid);

	ret = chmod_main(controller, cgroup, file, rcred, rcred, mode);
	if (ret)
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
					     "invalid request");
	return ret;
}

void get_value_complete(struct scm_sock_data *data)
{
	char *output = NULL;
	int ret;

	if (!get_value_main(data, data->controller, data->cgroup, data->key,
			data->pcred, data->rcred, &output))
		ret = write(data->fd, output, strlen(output)+1);
	else
		ret = write(data->fd, &data->rcred, 0);  // kick the client
	if (ret < 0)
		nih_error("GetValueScm: Error writing final result to client");
}

int cgmanager_get_value_scm (void *data, NihDBusMessage *message,
				 const char *controller, const char *req_cgroup,
				 const char *key, int sockfd)
{
	struct scm_sock_data *d;

	d = alloc_scm_sock_data(message, sockfd, REQ_TYPE_GET_VALUE);
	if (!d)
		return -1;
	d->controller = NIH_MUST( nih_strdup(d, controller) );
	d->cgroup = NIH_MUST( nih_strdup(d, req_cgroup) );
	d->key = NIH_MUST( nih_strdup(d, key) );

	if (!nih_io_reopen(NULL, sockfd, NIH_IO_MESSAGE,
				(NihIoReader) sock_scm_reader,
				(NihIoCloseHandler) scm_sock_close,
				scm_sock_error_handler, d)) {
		NihError *error = nih_error_steal ();
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed queue scm message: %s", error->message);
		nih_free(error);
		return -1;
	}
	if (!kick_fd_client(sockfd))
		return -1;
	return 0;

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
	int fd = 0, ret;
	struct ucred rcred;
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
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &rcred, &len) < 0) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
					     "Could not get peer cred: %s",
					     strerror(errno));
		return -1;
	}

	nih_info (_("GetValue: Client fd is: %d (pid=%d, uid=%u, gid=%u)"),
			fd, rcred.pid, rcred.uid, rcred.gid);

	ret = get_value_main(message, controller, req_cgroup, key, rcred, rcred, value);
	if (ret)
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
				"invalid request");
	return ret;
}

void set_value_complete(struct scm_sock_data *data)
{
	char b = '0';
	if (set_value_main(data->controller, data->cgroup, data->key,
				data->value, data->pcred, data->rcred) == 0)
		b = '1';
	if (write(data->fd, &b, 1) < 0)
		nih_error("SetValueScm: Error writing final result to client");
}

int cgmanager_set_value_scm (void *data, NihDBusMessage *message,
				 const char *controller, const char *req_cgroup,
				 const char *key, const char *value, int sockfd)
{
	struct scm_sock_data *d;

	d = alloc_scm_sock_data(message, sockfd, REQ_TYPE_SET_VALUE);
	if (!d)
		return -1;
	d->controller = NIH_MUST( nih_strdup(d, controller) );
	d->cgroup = NIH_MUST( nih_strdup(d, req_cgroup) );
	d->key = NIH_MUST( nih_strdup(d, key) );
	d->value = NIH_MUST( nih_strdup(d, value) );

	if (!nih_io_reopen(NULL, sockfd, NIH_IO_MESSAGE,
				(NihIoReader) sock_scm_reader,
				(NihIoCloseHandler) scm_sock_close,
				scm_sock_error_handler, d)) {
		NihError *error = nih_error_steal ();
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed queue scm message: %s", error->message);
		nih_free(error);
		return -1;
	}
	if (!kick_fd_client(sockfd))
		return -1;
	return 0;
}

/* 
 * This is one of the dbus callbacks.
 * Caller requests that a particular cgroup @key be set to @value
 * @controller is the controller, @req_cgroup the cgroup name, and @key the
 * file being queried (i.e. memory.usage_in_bytes).  @req_cgroup is relative
 * to the caller's cgroup.
 */
int cgmanager_set_value (void *data, NihDBusMessage *message,
				 const char *controller, const char *req_cgroup,
				 const char *key, const char *value)

{
	int fd = 0, ret;
	struct ucred rcred;
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
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &rcred, &len) < 0) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
					     "Could not get peer cred: %s",
					     strerror(errno));
		return -1;
	}

	nih_info (_("SetValue: Client fd is: %d (pid=%d, uid=%u, gid=%u)"),
			fd, rcred.pid, rcred.uid, rcred.gid);

	ret = set_value_main(controller, req_cgroup, key, value, rcred, rcred);
	if (ret)
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
					     "invalid request");
	return ret;
}

void remove_scm_complete(struct scm_sock_data *data)
{
	char b = '0';
	int ret;
	int32_t existed = -1;

	ret = remove_main(data->controller, data->cgroup, data->pcred,
			data->rcred, data->recursive, &existed);
	if (ret == 0)
		b = existed == 1 ? '2' : '1';
	if (write(data->fd, &b, 1) < 0)
		nih_error("removeScm: Error writing final result to client");
}

int cgmanager_remove_scm (void *data, NihDBusMessage *message,
		 const char *controller, const char *cgroup, int recursive, int sockfd)
{
	struct scm_sock_data *d;

	d = alloc_scm_sock_data(message, sockfd, REQ_TYPE_REMOVE);
	if (!d)
		return -1;
	d->controller = NIH_MUST( nih_strdup(d, controller) );
	d->cgroup = NIH_MUST( nih_strdup(d, cgroup) );
	d->recursive = recursive;

	if (!nih_io_reopen(NULL, sockfd, NIH_IO_MESSAGE,
				(NihIoReader) sock_scm_reader,
				(NihIoCloseHandler) scm_sock_close,
				scm_sock_error_handler, d)) {
		NihError *error = nih_error_steal ();
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed queue scm message: %s", error->message);
		nih_free(error);
		return -1;
	}
	if (!kick_fd_client(sockfd))
		return -1;
	return 0;
}

/* 
 * This is one of the dbus callbacks.
 * Caller requests creating a new @cgroup name of type @controller.
 * @name is taken to be relative to the caller's cgroup and may not
 * start with / or .. .
 */
int cgmanager_remove (void *data, NihDBusMessage *message, const char *controller,
			const char *cgroup, int recursive, int32_t *existed)
{
	int fd = 0, ret;
	struct ucred rcred;
	socklen_t len;

	*existed = -1;
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
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &rcred, &len) < 0) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
					     "Could not get peer cred: %s",
					     strerror(errno));
		return -1;
	}

	nih_info (_("Remove: Client fd is: %d (pid=%d, uid=%u, gid=%u)"),
			fd, rcred.pid, rcred.uid, rcred.gid);

	ret = remove_main(controller, cgroup, rcred, rcred, recursive, existed);
	if (ret)
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
					     "invalid request");
	return ret;
}

/* get_tasks - list tasks for a single cgroup */
void get_tasks_scm_complete(struct scm_sock_data *data)
{
	struct ucred pcred;
	int i, ret;
	pid_t firstvalid = -1;
	int32_t *pids, nrpids;
	ret = get_tasks_main(data, data->controller, data->cgroup,
			data->pcred, data->rcred, &pids);
	if (ret < 0) {
		nih_error("Error getting nrtasks for %s:%s for pid %d",
			data->controller, data->cgroup, data->rcred.pid);
		ret = -1;
	}
	nrpids = ret;
	if (write(data->fd, &nrpids, sizeof(int32_t)) != sizeof(int32_t)) {
		nih_error("get_tasks_scm: Error writing final result to client");
		return;
	}
	pcred.uid = 0; pcred.gid = 0;
	for (i=0; i<nrpids; i++) {
		pcred.pid = pids[i];
again:
		ret = send_creds(data->fd, &pcred);
		if (ret == -3) {
			if (firstvalid == -1 || firstvalid == pcred.pid) {
				nih_error("gettasks: too much pid churn.  Last valid pid was %d\n",
						firstvalid);
				return;
			}
			nih_info("gettasks: sending dup pid %d in place of exited pid %d\n",
					firstvalid, pcred.pid);
			pcred.pid = firstvalid;
			goto again;

		} else if (ret < 0)
			return;
		if (firstvalid == -1)
			firstvalid = pids[i];
	}
}

int cgmanager_get_tasks_scm (void *data, NihDBusMessage *message,
		 const char *controller, const char *cgroup, int sockfd)
{
	struct scm_sock_data *d;

	d = alloc_scm_sock_data(message, sockfd, REQ_TYPE_GET_TASKS);
	if (!d)
		return -1;
	d->controller = NIH_MUST( nih_strdup(d, controller) );
	d->cgroup = NIH_MUST( nih_strdup(d, cgroup) );

	if (!nih_io_reopen(NULL, sockfd, NIH_IO_MESSAGE,
				(NihIoReader) sock_scm_reader,
				(NihIoCloseHandler) scm_sock_close,
				scm_sock_error_handler, d)) {
		NihError *error = nih_error_steal ();
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed queue scm message: %s", error->message);
		nih_free(error);
		return -1;
	}
	if (!kick_fd_client(sockfd))
		return -1;
	return 0;
}

/* 
 * This is one of the dbus callbacks.
 * Caller requests the number of tasks in @cgroup in @controller
 * returns nrpids, or -1 on error.
 */
int cgmanager_get_tasks (void *data, NihDBusMessage *message, const char *controller,
			const char *cgroup, int32_t **pids, size_t *nrpids)
{
	int fd = 0, ret;
	struct ucred rcred;
	socklen_t len;
	int32_t *tmp;

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
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &rcred, &len) < 0) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
					     "Could not get peer cred: %s",
					     strerror(errno));
		return -1;
	}

	nih_info (_("GetTasks: Client fd is: %d (pid=%d, uid=%u, gid=%u)"),
			fd, rcred.pid, rcred.uid, rcred.gid);

	ret = get_tasks_main(message, controller, cgroup, rcred, rcred, &tmp);
	if (ret >= 0) {
		*nrpids = ret;
		*pids = tmp;
		ret = 0;
	} else
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
					     "invalid request");
	return ret;
}

/* GetTasksRecursive - list tasks for a cgroup and any descendents
 * inherintly racy. */
void get_tasks_recursive_scm_complete(struct scm_sock_data *data)
{
	struct ucred pcred;
	int i, ret;
	pid_t firstvalid = -1;
	int32_t *pids, nrpids;

	ret = get_tasks_recursive_main(data, data->controller, data->cgroup,
			data->pcred, data->rcred, &pids);
	if (ret < 0) {
		nih_error("Error getting nrtasks for %s:%s for pid %d",
			data->controller, data->cgroup, data->rcred.pid);
		ret = -1;
	}
	nrpids = ret;
	if (write(data->fd, &nrpids, sizeof(int32_t)) != sizeof(int32_t)) {
		nih_error("get_tasks_recursive_scm: Error writing final result to client");
		return;
	}
	pcred.uid = 0; pcred.gid = 0;
	for (i=0; i<nrpids; i++) {
		pcred.pid = pids[i];
again:
		ret = send_creds(data->fd, &pcred);
		if (ret == -3) {
			if (firstvalid == -1 || firstvalid == pcred.pid) {
				nih_error("gettasks: too much pid churn.  Last valid pid was %d\n",
						firstvalid);
				return;
			}
			nih_info("gettasks: sending dup pid %d in place of exited pid %d\n",
					firstvalid, pcred.pid);
			pcred.pid = firstvalid;
			goto again;
		} else if (ret < 0)
			return;
		if (firstvalid == -1)
			firstvalid = pids[i];
	}
}

int cgmanager_get_tasks_recursive_scm (void *data, NihDBusMessage *message,
		 const char *controller, const char *cgroup, int sockfd)
{
	struct scm_sock_data *d;

	d = alloc_scm_sock_data(message, sockfd, REQ_TYPE_GET_TASKS_RECURSIVE);
	if (!d)
		return -1;
	d->controller = NIH_MUST( nih_strdup(d, controller) );
	d->cgroup = NIH_MUST( nih_strdup(d, cgroup) );

	if (!nih_io_reopen(NULL, sockfd, NIH_IO_MESSAGE,
				(NihIoReader) sock_scm_reader,
				(NihIoCloseHandler) scm_sock_close,
				scm_sock_error_handler, d)) {
		NihError *error = nih_error_steal ();
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed queue scm message: %s", error->message);
		nih_free(error);
		return -1;
	}
	if (!kick_fd_client(sockfd))
		return -1;
	return 0;
}

/* 
 * This is one of the dbus callbacks.
 * Caller requests the number of tasks in @cgroup in @controller
 * returns nrpids, or -1 on error.
 */
int cgmanager_get_tasks_recursive (void *data, NihDBusMessage *message,
		const char *controller, const char *cgroup, int32_t **pids,
		size_t *nrpids)
{
	int fd = 0, ret;
	struct ucred rcred;
	socklen_t len;
	int32_t *tmp;

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
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &rcred, &len) < 0) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
					     "Could not get peer cred: %s",
					     strerror(errno));
		return -1;
	}

	nih_info (_("GetTasksRecursive: Client fd is: %d (pid=%d, uid=%u, gid=%u)"),
			fd, rcred.pid, rcred.uid, rcred.gid);

	ret = get_tasks_recursive_main(message, controller, cgroup, rcred, rcred, &tmp);
	if (ret >= 0) {
		*nrpids = ret;
		*pids = tmp;
		ret = 0;
	} else
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
					     "invalid request");
	return ret;
}


/* ListChildren - list child cgroups */
void list_children_scm_complete(struct scm_sock_data *data)
{
	int i, ret;
	uint32_t len = 0, remainlen;
	int32_t nrkids;
	char **output; // nih_alloced with data as parent; freed at io_shutdown
	nih_local char * path = NULL;
	char *p;

	nrkids = list_children_main(data, data->controller, data->cgroup,
			data->pcred, data->rcred, &output);
	if (write(data->fd, &nrkids, sizeof(int32_t)) != sizeof(int32_t)) {
		nih_error("%s: error writing results", __func__);
		return;
	}
	if (nrkids < 0) {
		nih_error("Error getting children for %s:%s for pid %d",
			data->controller, data->cgroup, data->rcred.pid);
		return;
	}
	if (nrkids == 0)  /* no names to write, we are done */
		return;

	for (i=0; i < nrkids; i++)
		len += strlen(output[i]) + 1;
	path = nih_alloc(NULL, len);
	if (!path) {
		nih_error("Out of memory");
		return;
	}
	p = path;
	remainlen = len;
	for (i=0; i < nrkids; i++) {
		ret = snprintf(p, remainlen, "%s", output[i]);
		if (ret < 0 || ret >= remainlen) // bogus
			return;
		p += ret + 1;
		remainlen -= ret + 1;
	}

	if (write(data->fd, &len, sizeof(uint32_t)) != sizeof(uint32_t)) {
		nih_error("%s: error writing results", __func__);
		return;
	}

	if (write(data->fd, path, len) != len) {
		nih_error("list_children_scm: Error writing final result to client");
		return;
	}
}

int cgmanager_list_children_scm (void *data, NihDBusMessage *message,
		 const char *controller, const char *cgroup, int sockfd)
{
	struct scm_sock_data *d;

	d = alloc_scm_sock_data(message, sockfd, REQ_TYPE_LIST_CHILDREN);
	if (!d)
		return -1;
	d->controller = NIH_MUST( nih_strdup(d, controller) );
	d->cgroup = NIH_MUST( nih_strdup(d, cgroup) );

	if (!nih_io_reopen(NULL, sockfd, NIH_IO_MESSAGE,
				(NihIoReader) sock_scm_reader,
				(NihIoCloseHandler) scm_sock_close,
				scm_sock_error_handler, d)) {
		NihError *error = nih_error_steal ();
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed queue scm message: %s", error->message);
		nih_free(error);
		return -1;
	}
	if (!kick_fd_client(sockfd))
		return -1;
	return 0;
}

/* 
 * This is one of the dbus callbacks.
 * Caller requests the number of tasks in @cgroup in @controller
 * returns nrpids, or -1 on error.
 */
int cgmanager_list_children (void *data, NihDBusMessage *message,
		const char *controller, const char *cgroup, char ***output)
{
	int fd = 0, ret;
	struct ucred rcred;
	socklen_t len;

	nih_assert(output);

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
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &rcred, &len) < 0) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
					     "Could not get peer cred: %s",
					     strerror(errno));
		return -1;
	}

	nih_info (_("ListChildren: Client fd is: %d (pid=%d, uid=%u, gid=%u)"),
			fd, rcred.pid, rcred.uid, rcred.gid);

	ret = list_children_main(message, controller, cgroup, rcred, rcred, output);
	if (ret >= 0)
		ret = 0;
	else
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
					     "invalid request");
	return ret;
}

void remove_on_empty_scm_complete(struct scm_sock_data *data)
{
	char b = '0';

	if (remove_on_empty_main(data->controller, data->cgroup, data->pcred,
				data->rcred) == 0)
		b = '1';
	if (write(data->fd, &b, 1) < 0)
		nih_error("RemoveOnEmptyScm: Error writing final result to client");
}

int cgmanager_remove_on_empty_scm (void *data, NihDBusMessage *message,
		 const char *controller, const char *cgroup, int sockfd)
{
	struct scm_sock_data *d;

	d = alloc_scm_sock_data(message, sockfd, REQ_TYPE_REMOVE_ON_EMPTY);
	if (!d)
		return -1;
	d->controller = NIH_MUST( nih_strdup(d, controller) );
	d->cgroup = NIH_MUST( nih_strdup(d, cgroup) );

	if (!nih_io_reopen(NULL, sockfd, NIH_IO_MESSAGE,
				(NihIoReader) sock_scm_reader,
				(NihIoCloseHandler) scm_sock_close,
				scm_sock_error_handler, d)) {
		NihError *error = nih_error_steal ();
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed queue scm message: %s", error->message);
		nih_free(error);
		return -1;
	}
	if (!kick_fd_client(sockfd))
		return -1;
	return 0;
}

/* 
 * This is one of the dbus callbacks.
 * Caller requests that cgroup @cgroup in controller @controller be
 * marked to be removed when it becomes empty, meaning there are no
 * more sub-cgroups and no tasks.
 */
int cgmanager_remove_on_empty (void *data, NihDBusMessage *message,
		const char *controller, const char *cgroup)
{
	int fd = 0, ret;
	struct ucred rcred;
	socklen_t len;

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
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &rcred, &len) < 0) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
					     "Could not get peer cred: %s",
					     strerror(errno));
		return -1;
	}

	nih_info (_("RemoveOnEmpty: Client fd is: %d (pid=%d, uid=%u, gid=%u)"),
			fd, rcred.pid, rcred.uid, rcred.gid);

	ret = remove_on_empty_main(controller, cgroup, rcred, rcred);
	if (ret >= 0)
		ret = 0;
	else
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
					     "invalid request");
	return ret;
}

/*
 * Prune - recursively call remove-on-empty first, then remove, on each
 * directory.
 */
void prune_scm_complete(struct scm_sock_data *data)
{
	char b = '0';

	if (prune_main(data->controller, data->cgroup, data->pcred,
				data->rcred) == 0)
		b = '1';
	if (write(data->fd, &b, 1) < 0)
		nih_error("PruneScm: Error writing final result to client");
}

int cgmanager_prune_scm (void *data, NihDBusMessage *message,
		 const char *controller, const char *cgroup, int sockfd)
{
	struct scm_sock_data *d;

	d = alloc_scm_sock_data(message, sockfd, REQ_TYPE_PRUNE);
	if (!d)
		return -1;
	d->controller = NIH_MUST( nih_strdup(d, controller) );
	d->cgroup = NIH_MUST( nih_strdup(d, cgroup) );

	if (!nih_io_reopen(NULL, sockfd, NIH_IO_MESSAGE,
				(NihIoReader) sock_scm_reader,
				(NihIoCloseHandler) scm_sock_close,
				scm_sock_error_handler, d)) {
		NihError *error = nih_error_steal ();
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed queue scm message: %s", error->message);
		nih_free(error);
		return -1;
	}
	if (!kick_fd_client(sockfd))
		return -1;
	return 0;
}

/* 
 * This is one of the dbus callbacks.
 * Caller requests that cgroup @cgroup in controller @controller be
 * recursively removed if empty, or else removed when it becomes empty.
 */
int cgmanager_prune (void *data, NihDBusMessage *message,
		const char *controller, const char *cgroup)
{
	int fd = 0, ret;
	struct ucred rcred;
	socklen_t len;

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
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &rcred, &len) < 0) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
					     "Could not get peer cred: %s",
					     strerror(errno));
		return -1;
	}

	nih_info (_("Prune: Client fd is: %d (pid=%d, uid=%u, gid=%u)"),
			fd, rcred.pid, rcred.uid, rcred.gid);

	ret = prune_main(controller, cgroup, rcred, rcred);
	if (ret >= 0)
		ret = 0;
	else
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
					     "invalid request");
	return ret;
}

/*
 * listcontrollers
 */
int cgmanager_list_controllers (void *data, NihDBusMessage *message,
		char ***output)
{
	int fd = 0, ret;
	struct ucred rcred;
	socklen_t len;

	nih_assert(output);

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
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &rcred, &len) < 0) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
					     "Could not get peer cred: %s",
					     strerror(errno));
		return -1;
	}

	nih_info (_("ListControllers: Client fd is: %d (pid=%d, uid=%u, gid=%u)"),
			fd, rcred.pid, rcred.uid, rcred.gid);

	ret = list_controllers_main(message, output);
	if (ret >= 0)
		ret = 0;
	else
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
					     "invalid request");
	return ret;
}

/*
 * listkeys - list the files in a specific controller:cgroup.
 * The return value will be written as a repeating list of:
 * ${name}\n${uid}\n${gid}\n${perms}\n
 */
void list_keys_scm_complete(struct scm_sock_data *data)
{
	int i;
	uint32_t len = 0;
	int32_t nrkeys;
	nih_local char *retdata = NULL;
	struct keys_return_type **output; // nih_alloced with data as parent; freed at io_shutdown

	nrkeys = list_keys_main(data, data->controller, data->cgroup,
			data->pcred, data->rcred, &output);
	if (write(data->fd, &nrkeys, sizeof(int32_t)) != sizeof(int32_t)) {
		nih_error("%s: error writing results", __func__);
		return;
	}
	if (nrkeys < 0) {
		nih_error("Error getting keys for %s:%s for pid %d",
			data->controller, data->cgroup, data->rcred.pid);
		return;
	}
	if (nrkeys == 0)  /* no names to write, we are done */
		return;

	for (i = 0; i < nrkeys; i++) {
		NIH_MUST( nih_strcat_sprintf(&retdata, NULL, "%s\n", output[i]->name) );
		NIH_MUST( nih_strcat_sprintf(&retdata, NULL, "%d\n", output[i]->uid) );
		NIH_MUST( nih_strcat_sprintf(&retdata, NULL, "%d\n", output[i]->gid) );
		NIH_MUST( nih_strcat_sprintf(&retdata, NULL, "%d\n", output[i]->perms) );
	}

	len = strlen(retdata);
	if (write(data->fd, &len, sizeof(uint32_t)) != sizeof(uint32_t)) {
		nih_error("%s: error writing results", __func__);
		return;
	}

	if (write(data->fd, retdata, len) != len) {
		nih_error("list_keysscm: Error writing final result to client");
		return;
	}
}

int cgmanager_list_keys_scm (void *data, NihDBusMessage *message,
		 const char *controller, const char *cgroup, int sockfd)
{
	struct scm_sock_data *d;

	d = alloc_scm_sock_data(message, sockfd, REQ_TYPE_LISTKEYS);
	if (!d)
		return -1;
	d->controller = NIH_MUST( nih_strdup(d, controller) );
	d->cgroup = NIH_MUST( nih_strdup(d, cgroup) );

	if (!nih_io_reopen(NULL, sockfd, NIH_IO_MESSAGE,
				(NihIoReader) sock_scm_reader,
				(NihIoCloseHandler) scm_sock_close,
				scm_sock_error_handler, d)) {
		NihError *error = nih_error_steal ();
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
			"Failed queue scm message: %s", error->message);
		nih_free(error);
		return -1;
	}
	if (!kick_fd_client(sockfd))
		return -1;
	return 0;
}

/* 
 * This is one of the dbus callbacks.
 * Caller requests the list of files in @cgroup in @controller
 * returns nrkeys, or -1 on error.
 */
int cgmanager_list_keys (void *data, NihDBusMessage *message,
		const char *controller, const char *cgroup,
		struct keys_return_type ***output)
{
	int fd = 0, ret;
	struct ucred rcred;
	socklen_t len;

	nih_assert(output);

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
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &rcred, &len) < 0) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
					     "Could not get peer cred: %s",
					     strerror(errno));
		return -1;
	}

	nih_info (_("ListKeys: Client fd is: %d (pid=%d, uid=%u, gid=%u)"),
			fd, rcred.pid, rcred.uid, rcred.gid);

	ret = list_keys_main(message, controller, cgroup, rcred, rcred, output);
	if (ret >= 0)
		ret = 0;
	else
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
					     "invalid request");
	return ret;
}

/*
 * return our API version
 */
int
cgmanager_get_api_version(void *data, NihDBusMessage *message, int *version)
{
	nih_assert(message);
	nih_assert(version);
	*version = API_VERSION;
	return 0;
}

static dbus_bool_t allow_user(DBusConnection *connection, unsigned long uid, void *data)
{
	return TRUE;
}

int client_connect (DBusServer *server, DBusConnection *conn)
{
	if (server == NULL || conn == NULL) {
		nih_error("client_connect called with bad arguments");
		return FALSE;
	}

	dbus_connection_set_unix_user_function(conn, allow_user, NULL, NULL);
	dbus_connection_set_allow_anonymous(conn, TRUE);

	nih_info (_("Connection from private client"));

	NIH_MUST (nih_dbus_object_new (NULL, conn,
				"/org/linuxcontainers/cgmanager",
				cgmanager_interfaces, NULL));

	return TRUE;
}

void client_disconnect (DBusConnection *conn)
{
	if (conn == NULL)
		return;

	nih_info (_("Disconnected from private client"));
}
