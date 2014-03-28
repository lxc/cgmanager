/* cgmanager
 *
 * Copyright © 2014 Canonical
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

#include <stdio.h>
#include <sys/types.h>

#include "cgmanager.h"
#include "cgmanager-client.h"

#include <nih-dbus/dbus_connection.h>
#include "cgmanager-client.h"
#include <nih/alloc.h>
#include <nih/error.h>
#include <nih/logging.h>
#include <nih/string.h>

#define CG_REMOVE_RECURSIVE 1

int do_remove_cgroup(const char *controller, const char *cgroup)
{
	DBusError dbus_error;
	DBusConnection *connection;
	dbus_error_init(&dbus_error);
	NihDBusProxy *cgroup_manager = NULL;

	connection = dbus_connection_open_private(CGMANAGER_DBUS_PATH, &dbus_error);
	if (!connection) {
		nih_error("Failed opening dbus connection: %s: %s",
				dbus_error.name, dbus_error.message);
		dbus_error_free(&dbus_error);
		return -1;
	}
	if (nih_dbus_setup(connection, NULL) < 0) {
		NihError *nerr;
		nerr = nih_error_get();
		nih_free(nerr);
		dbus_error_free(&dbus_error);
		dbus_connection_unref(connection);
		return -1;
	}
	dbus_error_free(&dbus_error);
	cgroup_manager = nih_dbus_proxy_new(NULL, connection,
				NULL /* p2p */,
				"/org/linuxcontainers/cgmanager", NULL, NULL);
	dbus_connection_unref(connection);
	if (!cgroup_manager) {
		NihError *nerr;
		nerr = nih_error_get();
		nih_free(nerr);
		return -1;
	}

	int existed;
	if ( cgmanager_remove_sync(NULL, cgroup_manager, controller,
				   cgroup, CG_REMOVE_RECURSIVE, &existed) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		nih_free(nerr);
	}
	nih_free(cgroup_manager);
	return 0;
}

int main(int argc, char *argv[])
{
	char *p;

	nih_assert (argv[1] != NULL);

	p = strstr(argv[0], ".");
	if (!p)
		return -1;

	/* controller is now in *(p+1), cgroup is in argv[1] */
	return do_remove_cgroup(p+1, argv[1]);
}
