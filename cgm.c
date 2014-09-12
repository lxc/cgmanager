/*
 *
 * Copyright © 2013 Serge Hallyn
 * Author: Serge Hallyn <serge.hallyn@ubuntu.com>
 *
 * based on cgroup.c from
 * lxc: linux Container library
 * (C) Copyright IBM Corp. 2007, 2008
 * Authors:
 * Daniel Lezcano <daniel.lezcano at free.fr>
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
#include <stdbool.h>
#include "cgmanager.h"
#include "cgmanager-client.h"

#include <nih/macros.h>
#include <nih/alloc.h>
#include <nih/string.h>
#include <nih/io.h>
#include <nih/option.h>
#include <nih/main.h>
#include <nih/logging.h>
#include <nih/error.h>
#include <nih/hash.h>

#include <nih-dbus/dbus_connection.h>
#include <nih-dbus/dbus_proxy.h>

static NihDBusProxy *cgroup_manager = NULL;

void usage(const char *me)
{
	printf("Usage:\n");
	printf("\n");
	printf("%s ping\n", me);
	printf("\n");
	printf("%s create <controller> <cgroup>\n", me);
	printf("\n");
	printf("%s chown <controller> <cgroup> uid gid\n", me);
	printf("\n");
	printf("%s chmod <controller> <cgroup> mode\n", me);
	printf("\n");
	printf("%s chmodfile <controller> <cgroup> file mode\n", me);
	printf("\n");
	printf("%s remove <controller> <cgroup> [0|1]\n", me);
	printf("\n");
	printf("%s getpidcgroup <controller> pid\n", me);
	printf("\n");
	printf("%s getpidcgroupabs <controller> pid\n", me);
	printf("\n");
	printf("%s movepid <controller> <cgroup> pid\n", me);
	printf("\n");
	printf("%s movepidabs <controller> <cgroup> pid\n", me);
	printf("\n");
	printf("%s getvalue <controller> <cgroup> file\n", me);
	printf("\n");
	printf("%s setvalue <controller> <cgroup> file value\n", me);
	printf("\n");
	printf("%s gettasks <controller> <cgroup>\n", me);
	printf("\n");
	printf("%s gettasksrecursive <controller> <cgroup>\n", me);
	printf("\n");
	printf("%s listchildren <controller> <cgroup>\n", me);
	printf("\n");
	printf("%s removeonempty <controller> <cgroup>\n", me);
	printf("\n");
	printf("%s prune <controller> <cgroup>\n", me);
	printf("\n");
	printf("%s listcontrollers\n", me);
	printf("\n");
	printf("%s listkeys <controller> <cgroup>\n", me);
	printf("\n");
	printf("%s apiversion\n", me);
	printf("\n");
	printf(" Replace '<controller>' with the desired controller, i.e.\n");
	printf(" memory, and '<cgroup>' with the desired cgroup, i.e. x1.\n");
	printf(" For create, chown, chmod, remove, prune, remove_on_empty,\n");
	printf(" gettasksrecursive and movepid, <controller> may be \"all\" or\n");
	printf(" a comma-separated set of cgroups.\n");
	printf(" Remove by default is recursive, but adding '0' as the last argument\n");
	printf(" will perforn non-recursive deletion.  Adding '1' is supported\n");
	printf(" for legacy reasons.\n");
	printf("\n");
	printf(" To refer to the current cgroup, use ''.\n");
	exit(1);
}

void connect_cgmanager(void)
{
	static DBusConnection *connection;
	DBusError dbus_error;

	dbus_error_init(&dbus_error);

	connection = dbus_connection_open_private(CGMANAGER_DBUS_PATH, &dbus_error);
	if (!connection) {
		fprintf(stderr, "Failed opening dbus connection: %s: %s\n",
				dbus_error.name, dbus_error.message);
		dbus_error_free(&dbus_error);
		exit(1);
	}
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
		exit(1);
	}
}

void do_ping(void)
{
	int a = 0;

	if (cgmanager_ping_sync(NULL, cgroup_manager, a) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to cgmanager_ping_sync failed: %s\n", nerr->message);
		nih_free(nerr);
		exit(1);
	}
	exit(0);
}

void do_create(const char *controller, const char *cgroup_path)
{
	int32_t existed = 0;
	if ( cgmanager_create_sync(NULL, cgroup_manager, controller,
				       cgroup_path, &existed) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to cgmanager_create_sync failed: %s\n", nerr->message);
		nih_free(nerr);
		exit(1);
	}
	if (existed == 1)
		printf("Path existed\n");
	exit(0);
}

#define CG_REMOVE_NONRECURSIVE 0
#define CG_REMOVE_RECURSIVE 1
void do_remove(const char *controller, const char *cgroup_path, bool recursive)
{
	int32_t existed = 0;
	if ( cgmanager_remove_sync(NULL, cgroup_manager, controller, cgroup_path,
				recursive ? CG_REMOVE_RECURSIVE : CG_REMOVE_NONRECURSIVE,
				&existed) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to cgmanager_remove_sync (%s) failed: %s\n",
			recursive ? "recursive" : "non-recursive", nerr->message);
		nih_free(nerr);
		exit(1);
	}
	if (existed == -1)
		printf("Path did not exist\n");
	exit(0);
}

void do_remove_on_empty(const char *controller, const char *cgroup_path)
{
	if ( cgmanager_remove_on_empty_sync(NULL, cgroup_manager, controller,
				       cgroup_path) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to cgmanager_remove_on_empty_sync failed: %s\n", nerr->message);
		nih_free(nerr);
		exit(1);
	}
	exit(0);
}

void do_chown(const char *controller, const char *cgroup_path,
		const char *uid, const char *gid)
{
	long u, g;

	u = strtol(uid, NULL, 10);
	g = strtol(gid, NULL, 10);
	if (u < 0 || g < 0 || u >= INT32_MAX || g >= INT32_MAX) {
		fprintf(stderr, "Bad uid or gid\n");
		exit(1);
	}

	if (cgmanager_chown_sync(NULL, cgroup_manager, controller,
			cgroup_path, (int32_t)u, (int32_t)g) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to cgmanager_chown_sync failed: %s\n", nerr->message);
		nih_free(nerr);
		exit(1);
	}
	exit(0);
}

void do_get_pid_cgroup(const char *controller, const char *pid)
{
	char *cgroup;

	if (cgmanager_get_pid_cgroup_sync(NULL, cgroup_manager, controller,
			atoi(pid), &cgroup) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to cgmanager_get_pid_cgroup_sync failed: %s\n", nerr->message);
		nih_free(nerr);
		exit(1);
	}
	printf("%s\n", cgroup);
	nih_free(cgroup);
	exit(0);
}

void do_get_pid_cgroupabs(const char *controller, const char *pid)
{
	char *cgroup = NULL;

	if (cgmanager_get_pid_cgroup_abs_sync(NULL, cgroup_manager, controller,
			atoi(pid), &cgroup) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to cgmanager_get_pid_cgroup_abs_sync failed: %s\n", nerr->message);
		nih_free(nerr);
		exit(1);
	}
	printf("%s\n", cgroup);
	nih_free(cgroup);
	exit(0);
}

void do_chmod(const char *controller, const char *cgroup_path, const char *mode)
{
	long m;

	m = strtol(mode, NULL, 8);
	if (m < 0 || m >= INT32_MAX) {
		fprintf(stderr, "Bad uid or gid\n");
		exit(1);
	}

	if (cgmanager_chmod_sync(NULL, cgroup_manager, controller,
			cgroup_path, "", (int32_t)m) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to cgmanager_chmod_sync failed: %s\n", nerr->message);
		nih_free(nerr);
		exit(1);
	}
	exit(0);
}

void do_chmodfile(const char *controller, const char *cgroup_path,
		const char *file, const char *mode)
{
	long m;

	m = strtol(mode, NULL, 8);
	if (m < 0 || m >= INT32_MAX) {
		fprintf(stderr, "Bad uid or gid\n");
		exit(1);
	}

	if (cgmanager_chmod_sync(NULL, cgroup_manager, controller,
			cgroup_path, file, (int32_t)m) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to cgmanager_chmod_sync failed: %s\n", nerr->message);
		nih_free(nerr);
		exit(1);
	}
	exit(0);
}

void do_move_pid(const char *controller, const char *cgroup_path, const char *pid)
{
	if (cgmanager_move_pid_sync(NULL, cgroup_manager, controller, cgroup_path,
				atoi(pid)) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to cgmanager_move_pid_main_sync failed: %s\n", nerr->message);
		nih_free(nerr);
		exit(1);
	}
	exit(0);
}

void do_move_pid_abs(const char *controller, const char *cgroup_path, const char *pid)
{
	if (cgmanager_move_pid_abs_sync(NULL, cgroup_manager, controller, cgroup_path,
				atoi(pid)) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to cgmanager_move_pid_main_sync failed: %s\n", nerr->message);
		nih_free(nerr);
		exit(1);
	}
	exit(0);
}

void do_getvalue(const char *controller, const char *cgroup_path, const char *file)
{
	char *value = NULL;
	if (cgmanager_get_value_sync(NULL, cgroup_manager, controller,
			cgroup_path, file, &value) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to cgmanager_get_value_sync failed: %s\n", nerr->message);
		nih_free(nerr);
		exit(1);
	}
	printf("%s\n", value);
	exit(0);
}

void do_setvalue(const char *controller, const char *cgroup_path, const char *file,
		const char *value)
{
	if (cgmanager_set_value_sync(NULL, cgroup_manager, controller,
			cgroup_path, file, value) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to cgmanager_set_value_sync failed: %s\n", nerr->message);
		nih_free(nerr);
		exit(1);
	}
	exit(0);
}

void do_gettasks(const char *controller, const char *cgroup_path)
{
	int32_t *pids = NULL;
	int i;
	size_t pids_len = -1;

	if (cgmanager_get_tasks_sync(NULL, cgroup_manager, controller,
				     cgroup_path, &pids, &pids_len) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		if (pids_len != 0)
			fprintf(stderr, "call to cgmanager_get_tasks_sync failed: %s\n", nerr->message);
		nih_free(nerr);
		if (pids_len != 0)
			exit(1);
	}
	for (i = 0;  i < pids_len;  i++) {
		printf("%d\n", pids[i]);
	}
	if (i)
		nih_free(pids);
	exit(0);
}

void do_gettasks_recursive(const char *controller, const char *cgroup_path)
{
	int32_t *pids = NULL;
	int i;
	size_t pids_len = -1;

	if (cgmanager_get_tasks_recursive_sync(NULL, cgroup_manager, controller,
				     cgroup_path, &pids, &pids_len) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		if (pids_len != 0)
			fprintf(stderr, "call to cgmanager_get_tasks_recursive_sync failed: %s\n", nerr->message);
		nih_free(nerr);
		if (pids_len != 0)
			exit(1);
	}
	for (i = 0;  i < pids_len;  i++) {
		printf("%d\n", pids[i]);
	}
	if (i)
		nih_free(pids);
	exit(0);
}

void do_listchildren(const char *controller, const char *cgroup_path)
{
	char **children = NULL;
	int i = 0;

	if (cgmanager_list_children_sync(NULL, cgroup_manager, controller,
				cgroup_path, &children) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to cgmanager_list_children_sync failed: %s\n", nerr->message);
		nih_free(nerr);
		exit(1);
	}

	while (children[i]) {
		printf("%s\n", children[i++]);
	}
	nih_free(children);
	exit(0);
}

void do_prune(const char *controller, const char *cgroup_path)
{
	if ( cgmanager_prune_sync(NULL, cgroup_manager, controller, cgroup_path) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to cgmanager_prune_sync failed: %s\n", nerr->message);
		nih_free(nerr);
		exit(1);
	}
	exit(0);
}

void do_listcontrollers(void)
{
	char **controllers = NULL;
	int i = 0;

	if (cgmanager_list_controllers_sync(NULL, cgroup_manager, &controllers) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to cgmanager_list_controllers_sync failed: %s\n", nerr->message);
		nih_free(nerr);
		exit(1);
	}

	while (controllers[i]) {
		printf("%s\n", controllers[i++]);
	}
	nih_free(controllers);
	exit(0);
}

void do_listkeys(const char *controller, const char *cgroup_path)
{
	CgmanagerListKeysOutputElement **keys = NULL;
	int i = 0;

	if (cgmanager_list_keys_sync(NULL, cgroup_manager, controller,
				cgroup_path, &keys) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to cgmanager_list_keys_sync failed: %s\n", nerr->message);
		nih_free(nerr);
		exit(1);
	}

	while (keys[i]) {
		printf("%s %u %u %o\n", keys[i]->item0, keys[i]->item1,
			keys[i]->item2, keys[i]->item3);
		i++;
	}
	nih_free(keys);
	exit(0);
}

void do_apiversion(void)
{
	int32_t v;

	if (cgmanager_get_api_version_sync(NULL, cgroup_manager, &v) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		fprintf(stderr, "call to cgmanager_get_api_version_sync failed: %s\n", nerr->message);
		nih_free(nerr);
		exit(1);
	}
	printf("%d\n", v);
	exit(0);
}

void print_version(void)
{
	printf("0.29");
	exit(0);
}

int main(int argc, const char *argv[])
{
	const char *me;

	if ((me = strrchr(argv[0], '/')))
		me++;
	else
		me = argv[0];

	if (strncmp(me, "lt-", 3) == 0 && strlen(me) > 3)
		me += 3;

	if (argc < 2)
		usage(me);

	if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)
		usage(me);

	if (strcmp(argv[1], "--version") == 0)
		print_version();

	connect_cgmanager();

	if (strcmp(argv[1], "ping") == 0) {
		do_ping();
	} else if (strcmp(argv[1], "create") == 0) { 
		if (argc != 4)
			usage(me);
		do_create(argv[2], argv[3]);
	} else if (strcmp(argv[1], "chown") == 0) { 
		if (argc != 6)
			usage(me);
		do_chown(argv[2], argv[3], argv[4], argv[5]);
	} else if (strcmp(argv[1], "chmod") == 0) { 
		if (argc != 5)
			usage(me);
		do_chmod(argv[2], argv[3], argv[4]);
	} else if (strcmp(argv[1], "chmodfile") == 0) { 
		if (argc != 6)
			usage(me);
		do_chmodfile(argv[2], argv[3], argv[4], argv[5]);
	} else if (strcmp(argv[1], "remove") == 0) { 
		bool recursive = true;
		if (argc != 4 && argc != 5)
			usage(me);
		if (argc == 5 && strcmp(argv[4], "0") == 0)
			recursive = false;
		do_remove(argv[2], argv[3], recursive);
	} else if (strcmp(argv[1], "removeonempty") == 0) { 
		if (argc != 4)
			usage(me);
		do_remove_on_empty(argv[2], argv[3]);
	} else if (strcmp(argv[1], "getpidcgroup") == 0) { 
		if (argc != 4)
			usage(me);
		do_get_pid_cgroup(argv[2], argv[3]);
	} else if (strcmp(argv[1], "getpidcgroupabs") == 0) { 
		if (argc != 4)
			usage(me);
		do_get_pid_cgroupabs(argv[2], argv[3]);
	} else if (strcmp(argv[1], "movepid") == 0) { 
		if (argc != 5)
			usage(me);
		do_move_pid(argv[2], argv[3], argv[4]);
	} else if (strcmp(argv[1], "movepidabs") == 0) { 
		if (argc != 5)
			usage(me);
		do_move_pid_abs(argv[2], argv[3], argv[4]);
	} else if (strcmp(argv[1], "getvalue") == 0) { 
		if (argc != 5)
			usage(me);
		do_getvalue(argv[2], argv[3], argv[4]);
	} else if (strcmp(argv[1], "setvalue") == 0) { 
		if (argc != 6)
			usage(me);
		do_setvalue(argv[2], argv[3], argv[4], argv[5]);
	} else if (strcmp(argv[1], "gettasksrecursive") == 0) { 
		if (argc != 3 && argc != 4)
			usage(me);
		do_gettasks_recursive(argv[2], argc == 3 ? "" : argv[3]);
	} else if (strcmp(argv[1], "gettasks") == 0) { 
		if (argc != 3 && argc != 4)
			usage(me);
		do_gettasks(argv[2], argc == 3 ? "" : argv[3]);
	} else if (strcmp(argv[1], "listchildren") == 0) { 
		if (argc != 3 && argc != 4)
			usage(me);
		do_listchildren(argv[2], argc == 3 ? "" : argv[3]);
	} else if (strcmp(argv[1], "prune") == 0) { 
		if (argc != 3 && argc != 4)
			usage(me);
		do_prune(argv[2], argc == 3 ? "" : argv[3]);
	} else if (strcmp(argv[1], "listcontrollers") == 0) { 
		do_listcontrollers();
	} else if (strcmp(argv[1], "listkeys") == 0) { 
		if (argc != 3 && argc != 4)
			usage(me);
		do_listkeys(argv[2], argc == 3 ? "" : argv[3]);
	} else if (strcmp(argv[1], "apiversion") == 0) { 
		do_apiversion();
	} else {
		printf("Unknown command: %s\n", argv[1]);
		usage(me);
	}
	// notreached
	exit(0);
}
