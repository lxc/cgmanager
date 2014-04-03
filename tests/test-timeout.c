/* concurrent.c
 *
 * Copyright © 2013 S.Çağlar Onur <caglar@10ur.org>
 * Copyright © 2014 Serge Hallyn <serge.hallyn@ubuntu.com>
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
 *
 * compile with
gcc -o cgm-concurrent cgm-concurrent.c -I/usr/include/dbus-1.0 -I/usr/lib/x86_64-linux-gnu/dbus-1.0/include -I/usr/include/cgmanager -lcgmanager -lnih -lnih-dbus -ldbus-1 -I/usr/include/dbus-1.0 -I/usr/lib/x86_64-linux-gnux/dbus-1.0/include -ldbus-1 -lpthread -g XXX
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
#include <netinet/in.h>
#include <net/if.h>
#include <sys/syscall.h>

#include <limits.h>
#include <malloc.h>
#include <getopt.h>
#include <stdlib.h>

#include <nih-dbus/dbus_connection.h>
#include <cgmanager/cgmanager-client.h>
#include <nih/alloc.h>
#include <nih/error.h>
#include <nih/string.h>
#include <stdbool.h>
#include <cgmanager-client.h>

NihDBusProxy *cgroup_manager = NULL;
DBusConnection *connection = NULL;

static const struct option options[] = {
	{ "threads",     required_argument, NULL, 'j' },
	{ "iterations",  required_argument, NULL, 'i' },
	{ "connect-only",  no_argument, NULL, 'c' },
	{ 0, 0, 0, 0 },
};

void cgm_dbus_disconnected(DBusConnection *connection)
{
	cgroup_manager = NULL;
	connection = NULL;
}

static void cgm_dbus_disconnect(void)
{
	if (cgroup_manager)
		nih_free(cgroup_manager);
	cgroup_manager = NULL;
	if (connection) {
		dbus_connection_flush(connection);
		dbus_connection_close(connection);
		dbus_connection_unref(connection);
	}
	connection = NULL;
}

#define CGMANAGER_DBUS_SOCK "unix:path=/sys/fs/cgroup/cgmanager/sock"
static bool cgm_dbus_connect(void)
{
	DBusError dbus_error;

	dbus_error_init(&dbus_error);

	connection = nih_dbus_connect(CGMANAGER_DBUS_SOCK, cgm_dbus_disconnected);
	if (!connection) {
		dbus_error_free(&dbus_error);
		return false;
	}
	dbus_connection_set_exit_on_disconnect(connection, FALSE);
	dbus_error_free(&dbus_error);
	cgroup_manager = nih_dbus_proxy_new(NULL, connection,
				NULL /* p2p */,
				"/org/linuxcontainers/cgmanager", NULL, NULL);
	if (!cgroup_manager) {
		NihError *nerr;
		nerr = nih_error_get();
		nih_free(nerr);
		cgm_dbus_disconnect();
		return false;
	}

	// force fd passing negotiation
	if (cgmanager_ping_sync(NULL, cgroup_manager, 0) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		nih_free(nerr);
		cgm_dbus_disconnect();
		return false;
	}
	return true;
}

int main(int argc, char *argv[]) {

	int32_t v;
	NihError *nerr;

	if (!cgm_dbus_connect()) {
		fprintf(stderr, "Error connecting to dbus\n");
		exit(1);
	}

	sleep(30);
	if (cgmanager_ping_sync(NULL, cgroup_manager, v) == 0) {
		fprintf(stderr, "connection did not time out");
		exit(1);
	}
	nerr = nih_error_get();
	nih_free(nerr);

	/* Now open a connection, wait 15 seconds, do a request,
	 * wait another 15 seconds - connection should still be open;
	 * wait anothe 15 seconds, it should be closed.
	 */
	if (!cgm_dbus_connect()) {
		fprintf(stderr, "Error connecting to dbus\n");
		exit(1);
	}
	sleep(15);
	if (cgmanager_get_api_version_sync(NULL, cgroup_manager, &v) != 0) {
		nerr = nih_error_get();
		nih_free(nerr);
		fprintf(stderr, "Error creating freezer cgroup\n");
		exit(1);
	}
	sleep(15);
	if (cgmanager_ping_sync(NULL, cgroup_manager, v) != 0) {
		nerr = nih_error_get();
		nih_free(nerr);
		fprintf(stderr, "timeout was not reset");
		exit(1);
	}
	sleep(30);
	if (cgmanager_ping_sync(NULL, cgroup_manager, v) == 0) {
		fprintf(stderr, "connection did not time out after a reset");
		exit(1);
	}
	nerr = nih_error_get();
	nih_free(nerr);
	fprintf(stderr, "all tests passed\n");
	exit(0);
}
