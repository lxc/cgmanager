/* pam-cgm
 *
 * Copyright © 2015 Canonical, Inc
 * Author: Serge Hallyn <serge.hallyn@ubuntu.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <ctype.h>
#include <pthread.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/inotify.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <net/if.h>
#include <stdbool.h>

#include <nih-dbus/dbus_connection.h>
#include <cgmanager/cgmanager-client.h>
#include <nih/alloc.h>
#include <nih/error.h>
#include <nih/string.h>

#include "cgmanager.h"

static NihDBusProxy *cgroup_manager = NULL;
static int32_t api_version;

void cgm_dbus_disconnect(void)
{
       if (cgroup_manager) {
	       dbus_connection_flush(cgroup_manager->connection);
	       dbus_connection_close(cgroup_manager->connection);
               nih_free(cgroup_manager);
       }
       cgroup_manager = NULL;
}

char *ctrl_list;

#define CGMANAGER_DBUS_SOCK "unix:path=/sys/fs/cgroup/cgmanager/sock"
bool cgm_dbus_connect(void)
{
	DBusError dbus_error;
	static DBusConnection *connection;

	dbus_error_init(&dbus_error);

	connection = dbus_connection_open_private(CGMANAGER_DBUS_SOCK, &dbus_error);
	if (!connection) {
		fprintf(stderr, "Failed opening dbus connection: %s: %s\n",
				dbus_error.name, dbus_error.message);
		dbus_error_free(&dbus_error);
		return false;
	}
	dbus_connection_set_exit_on_disconnect(connection, FALSE);
	dbus_error_free(&dbus_error);
	cgroup_manager = nih_dbus_proxy_new(NULL, connection,
				NULL /* p2p */,
				"/org/linuxcontainers/cgmanager", NULL, NULL);
	dbus_connection_unref(connection);
	if (!cgroup_manager) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "Error opening cgmanager proxy: %s\n", nerr->message);
		nih_free(nerr);
		cgm_dbus_disconnect();
		return false;
	}

	// get the api version
	if (cgmanager_get_api_version_sync(NULL, cgroup_manager, &api_version) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "Error cgroup manager api version: %s\n", nerr->message);
		nih_free(nerr);
		cgm_dbus_disconnect();
		return false;
	}

	return true;
}

bool cgm_create(const char *cg, int32_t *existed)
{
	if ( cgmanager_create_sync(NULL, cgroup_manager, ctrl_list, cg, existed) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to create failed (%s:%s): %s\n", ctrl_list, cg, nerr->message);
		nih_free(nerr);
		return false;
	}
	return true;
}

bool cgm_autoremove(const char *cg)
{
	if ( cgmanager_remove_on_empty_sync(NULL, cgroup_manager, ctrl_list, cg) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to remove-on-empty (%s:%s) failed: %s\n", ctrl_list, cg, nerr->message);
		nih_free(nerr);
		return false;
	}
	return true;
}

bool cgm_enter(const char *cg)
{
	if ( cgmanager_move_pid_sync(NULL, cgroup_manager, ctrl_list, cg,
				(int32_t) getpid()) != 0 ) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to move_pid (%s:%s, %d) failed: %s\n", ctrl_list, cg, (int)getpid(), nerr->message);
		nih_free(nerr);
		return false;
	}
	return true;
}

bool cgm_chown(const char *cg, uid_t uid, gid_t gid)
{
	if ( cgmanager_chown_sync(NULL, cgroup_manager, ctrl_list, cg, uid, gid) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to chown (%s:%s, %d, %d) failed: %s\n", ctrl_list, cg, uid, gid, nerr->message);
		nih_free(nerr);
		return false;
	}
	return true;
}

char **cgm_list_controllers(void)
{
	char **controllers;
	if ( cgmanager_list_controllers_sync(NULL, cgroup_manager, &controllers) != 0 ) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to list_controllers failed: %s\n", nerr->message);
		nih_free(nerr);
		return NULL;
	}
	return controllers;
}

/*
 * We can't list_children on >1 (not-comounted) controllers.
 * So choose the first controller and get the children of it
 */
char **cgm_list_children(const char *cg)
{
	char **children;
	nih_local char *ctrl = NIH_MUST( nih_strdup(NULL, ctrl_list) );
	char *p = strchr(ctrl, ',');
	if (p)
		*p = '\0';
	if ( cgmanager_list_children_sync(NULL, cgroup_manager, ctrl, cg, &children) != 0 ) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to list_children failed: %s\n", nerr->message);
		nih_free(nerr);
		return NULL;
	}
	return children;
}

bool cgm_cg_has_tasks(const char *cg)
{
	nih_local int32_t * pids;
	size_t len;

	if ( cgmanager_get_tasks_recursive_sync(NULL, cgroup_manager, ctrl_list, cg, &pids, &len) != 0 ) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to get_tasks_recursive failed: %s\n", nerr->message);
		nih_free(nerr);
		return false;
	}
	return len > 0;
}

void cgm_clear_cgroup(const char *cg)
{
	int32_t recursive = 1;
	int32_t existed;

	if ( cgmanager_remove_sync(NULL, cgroup_manager, ctrl_list, cg, recursive, &existed) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "warning: call to remove(%s) failed: %s\n", cg, nerr->message);
		nih_free(nerr);
	}
}

void cgm_escape(void)
{
	if ( cgmanager_move_pid_abs_sync(NULL, cgroup_manager, ctrl_list, "/", (int32_t) getpid()) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "warning: attempt to escape to root cgroup failed: %s\n", nerr->message);
		nih_free(nerr);
	}
}
