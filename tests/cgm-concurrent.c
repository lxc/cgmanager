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

static __thread NihDBusProxy *cgroup_manager = NULL;
static __thread DBusConnection *connection = NULL;

static const struct option options[] = {
	{ "threads",     required_argument, NULL, 'j' },
	{ "iterations",  required_argument, NULL, 'i' },
	{ "connect-only",  no_argument, NULL, 'c' },
	{ 0, 0, 0, 0 },
};

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

	connection = dbus_connection_open_private(CGMANAGER_DBUS_SOCK, &dbus_error);
	if (!connection) {
		dbus_error_free(&dbus_error);
		return false;
	}
	if (nih_dbus_setup(connection, NULL) < 0) {
		NihError *nerr;
		nerr = nih_error_get();
		nih_free(nerr);
		dbus_error_free(&dbus_error);
		dbus_connection_unref(connection);
		connection = NULL;
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

static inline int gettid(void)
{
	return (int)syscall(__NR_gettid);
}

bool connect_only = false;

static void do_function(void *arguments)
{
	char path[100];
	int existed;
	char *value;

	if (!cgm_dbus_connect()) {
		fprintf(stderr, "Error connecting to dbus\n");
		return;
	}

	sprintf(path, "cgmtest-%d", gettid());

	if (connect_only) {
		if (cgmanager_create_sync(NULL, cgroup_manager, "freezer", path, &existed) != 0) {
			fprintf(stderr, "Error creating freezer cgroup\n");
			exit(1);
		}
		if (cgmanager_get_value_sync(NULL, cgroup_manager, "freezer", path, "freezer.state", &value) != 0) {
			fprintf(stderr, "Error querying freezer cgroup\n");
			exit(1);
		}
		if (cgmanager_remove_sync(NULL, cgroup_manager, "freezer", path, 1, &existed) != 0) {
			fprintf(stderr, "Error removing freezer cgroup\n");
			exit(1);
		}
	}
	cgm_dbus_disconnect();
}

static void *concurrent(void *arguments)
{
    do_function(arguments);
    pthread_exit(NULL);

    return NULL;
}

void usage(char *me)
{
    printf("Usage: %s [-i nrruns] [-j nrthreads]\n", me);
    printf("   nrruns defaults to 10\n");
    printf("   nrthreads defaults to 5\n");
}

int main(int argc, char *argv[]) {

    pthread_t *threads;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    int i, j, nthreads = 5, iterations=5, opt;

    while ((opt = getopt_long(argc, argv, "j:i:c", options, NULL)) != -1) {
        switch(opt) {
            case 'j':
                nthreads = atoi(optarg);
                break;
            case 'i':
                iterations = atoi(optarg);
                break;
	    case 'c':
	    	connect_only = true;
		break;
            default:
                usage(argv[0]);
                exit(1);
        }
    }
    dbus_threads_init_default();
    threads = malloc(sizeof(*threads) * nthreads);
    pthread_attr_init(&attr);

    for (i = 0; i < iterations; i++) {
        for (j = 0; j < nthreads; j++) {
            if (pthread_create(&threads[j], &attr, concurrent, NULL) != 0) {
                perror("pthread_create() error");
                exit(1);
            }

        }
        for (j = 0; j < nthreads; j++) {
            if (pthread_join(threads[j], NULL) != 0) {
                perror("pthread_join() error");
                exit(EXIT_FAILURE);
            }
        }
    }

    pthread_attr_destroy(&attr);
    free(threads);
    exit(0);
}
