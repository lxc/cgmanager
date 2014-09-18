/* frontend.h: Prototypes for the dbus and scm-enhanced dbus
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

#ifndef __frontend_h
#define __frontend_h

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

#include "config.h"

/**
 * daemonise:
 *
 * Set to TRUE if we should become a daemon, rather than just running
 * in the foreground.
 **/
#ifndef __frontend_c
extern int daemonise;
extern int sigstop;
extern bool setns_pid_supported;
extern unsigned long mypidns;
extern bool setns_user_supported;
extern unsigned long myuserns;
#endif

struct scm_sock_data {
	int type;
	char *controller;
	char *cgroup;
	char *key;
	char *value;
	int step;
	struct ucred	pcred, // proxy credential
			rcred, // requestor credential
			vcred; // victim credential
	int fd;
	int recursive;
	int mode;
	char *file;
};

enum req_type {
	REQ_TYPE_GET_PID,
	REQ_TYPE_MOVE_PID,
	REQ_TYPE_CREATE,
	REQ_TYPE_CHOWN,
	REQ_TYPE_GET_VALUE,
	REQ_TYPE_SET_VALUE,
	REQ_TYPE_REMOVE,
	REQ_TYPE_GET_TASKS,
	REQ_TYPE_GET_TASKS_RECURSIVE,
	REQ_TYPE_CHMOD,
	REQ_TYPE_MOVE_PID_ABS,
	REQ_TYPE_LIST_CHILDREN,
	REQ_TYPE_REMOVE_ON_EMPTY,
	REQ_TYPE_GET_PID_ABS,
	REQ_TYPE_PRUNE,
	REQ_TYPE_LISTCONTROLLERS,
	REQ_TYPE_LISTKEYS,
};

struct keys_return_type {
	char *name;
	uint32_t uid;
	uint32_t gid;
	uint32_t perms;
};

int get_pid_cgroup_main(void *parent, const char *controller,
		struct ucred p, struct ucred r, struct ucred v, char **output);
void get_pid_scm_complete(struct scm_sock_data *data);
int get_pid_cgroup_abs_main(void *parent, const char *controller,
		struct ucred p, struct ucred r, struct ucred v, char **output);
void get_pid_abs_scm_complete(struct scm_sock_data *data);
int move_pid_main(const char *controller, const char *cgroup,
		struct ucred p, struct ucred r, struct ucred v);
void move_pid_scm_complete(struct scm_sock_data *data);
int move_pid_abs_main(const char *controller, const char *cgroup,
		struct ucred p, struct ucred r, struct ucred v);
void move_pid_abs_scm_complete(struct scm_sock_data *data);
int create_main(const char *controller, const char *cgroup,
		struct ucred p, struct ucred r, int32_t *existed);
void create_scm_complete(struct scm_sock_data *data);
int chown_main(const char *controller, const char *cgroup,
		struct ucred p, struct ucred r, struct ucred v);
void chown_scm_complete(struct scm_sock_data *data);
int chmod_main(const char *controller, const char *cgroup, const char *file,
		struct ucred p, struct ucred r, int mode);
void chmod_scm_complete(struct scm_sock_data *data);
int get_value_main(void *parent, const char *controller,
		const char *req_cgroup, const char *key,
		struct ucred p, struct ucred r, char **value);
void get_value_complete(struct scm_sock_data *data);
int set_value_main(const char *controller, const char *req_cgroup,
		const char *key, const char *value,
		struct ucred p, struct ucred r);
void set_value_complete(struct scm_sock_data *data);
int remove_main(const char *controller, const char *cgroup, struct ucred p,
		struct ucred r, int recursive, int32_t *existed);
void remove_scm_complete(struct scm_sock_data *data);
int get_tasks_main (void *parent, const char *controller, const char *cgroup,
		struct ucred p, struct ucred r, int32_t **pids);
void get_tasks_scm_complete(struct scm_sock_data *data);
int get_tasks_recursive_main (void *parent, const char *controller,
		const char *cgroup, struct ucred p, struct ucred r, int32_t **pids);
void get_tasks_recursive_scm_complete(struct scm_sock_data *data);
int list_children_main (void *parent, const char *controller, const char *cgroup,
		struct ucred p, struct ucred r, char ***output);
void list_children_scm_complete(struct scm_sock_data *data);

int remove_on_empty_main (const char *controller, const char *cgroup,
		struct ucred p, struct ucred r);
void remove_on_empty_scm_complete(struct scm_sock_data *data);

int prune_main (const char *controller, const char *cgroup,
		struct ucred p, struct ucred r);
void prune_scm_complete(struct scm_sock_data *data);

int list_controllers_main (void *parent, char ***output);

int list_keys_main (void *parent, const char *controller, const char *cgroup,
			struct ucred p, struct ucred r,
			struct keys_return_type ***output);
void list_keys_scm_complete (struct scm_sock_data *data);

int cgmanager_ping (void *data, NihDBusMessage *message, int junk);

int client_connect (DBusServer *server, DBusConnection *conn);
void client_disconnect (DBusConnection *conn);

bool sane_cgroup(const char *cgroup);

#define API_VERSION 10

#endif
