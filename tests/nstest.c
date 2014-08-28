/* nstest
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

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sched.h>

#include <nih-dbus/dbus_connection.h>
#include <cgmanager/cgmanager-client.h>
#include <nih/alloc.h>
#include <nih/error.h>
#include <nih/string.h>
#include <stdbool.h>
#include <cgmanager-client.h>

const char *mycmd;
int tochild[2], fromchild[2];

const char *controller = "freezer";

static NihDBusProxy *cgroup_manager = NULL;
static int32_t api_version;

static void cgmanager_disconnect(void)
{
       if (cgroup_manager) {
	       dbus_connection_flush(cgroup_manager->connection);
	       dbus_connection_close(cgroup_manager->connection);
               nih_free(cgroup_manager);
       }
       cgroup_manager = NULL;
}

#define CGMANAGER_DBUS_SOCK "unix:path=/sys/fs/cgroup/cgmanager/sock"
static void cgmanager_connect(void)
{
	DBusError dbus_error;
	static DBusConnection *connection;

	dbus_error_init(&dbus_error);

	connection = dbus_connection_open_private(CGMANAGER_DBUS_SOCK, &dbus_error);
	if (!connection) {
		printf("Failed opening dbus connection: %s: %s\n",
				dbus_error.name, dbus_error.message);
		dbus_error_free(&dbus_error);
		exit(1);
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
		printf("Error opening cgmanager proxy: %s\n", nerr->message);
		nih_free(nerr);
		exit(1);
	}

	// get the api version
	if (cgmanager_get_api_version_sync(NULL, cgroup_manager, &api_version) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		printf("Error cgroup manager api version: %s\n", nerr->message);
		nih_free(nerr);
		exit(1);
	}
}

static int send_creds(int sock, int rpid, int ruid, int rgid)
{
	struct msghdr msg = { 0 };
	struct iovec iov;
	struct cmsghdr *cmsg;
	struct ucred cred = {
		.pid = rpid,
		.uid = ruid,
		.gid = rgid,
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

	if (sendmsg(sock, &msg, 0) < 0)
		return -1;
	return 0;
}

void create(const char *cg)
{
	int32_t existed;
	cgmanager_connect();
	if ( cgmanager_create_sync(NULL, cgroup_manager, controller, cg, &existed) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		printf("call to cgmanager_create_sync failed: %s\n", nerr->message);
		nih_free(nerr);
		cgmanager_disconnect();
		exit(1);
	}
	cgmanager_disconnect();
}

void movepid(const char *cg, pid_t pid)
{
	int sv[2] = {-1, -1}, optval = 1, ret = -1;
	char buf[1];

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
		printf("Error creating socketpair: %m\n");
		exit(1);
	}
	if (setsockopt(sv[1], SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
		printf("setsockopt failed: %m\n");
		exit(1);
	}
	if (setsockopt(sv[0], SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
		printf("setsockopt failed: %m\n");
		exit(1);
	}
	cgmanager_connect();
	if ( cgmanager_move_pid_scm_sync(NULL, cgroup_manager, controller, cg, sv[1]) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		printf("call to cgmanager_move_pid_scm_sync failed: %s\n", nerr->message);
		nih_free(nerr);
		cgmanager_disconnect();
		exit(1);
	}
	fd_set rfds;
	FD_ZERO(&rfds);
	FD_SET(sv[0], &rfds);
	if (select(sv[0]+1, &rfds, NULL, NULL, NULL) < 0) {
		printf("Error getting go-ahead from server: %s\n", strerror(errno));
		exit(1);
	}
	if (read(sv[0], &buf, 1) != 1) {
		printf("Error getting reply from server over socketpair: %m\n");
		exit(1);
	}
	if (send_creds(sv[0], getpid(), getuid(), getgid())) {
		printf("%s: Error sending my pid over SCM_CREDENTIAL: %m\n", __func__);
		exit(1);
	}
	FD_ZERO(&rfds);
	FD_SET(sv[0], &rfds);
	if (select(sv[0]+1, &rfds, NULL, NULL, NULL) < 0) {
		printf("Error getting go-ahead from server: %s\n", strerror(errno));
		exit(1);
	}
	if (read(sv[0], &buf, 1) != 1) {
		printf("Error getting reply from server over socketpair: %m\n");
		exit(1);
	}
	if (send_creds(sv[0], pid, 0, 0)) {
		printf("%s: Error sending victim pid over SCM_CREDENTIAL: %m\n", __func__);
		exit(1);
	}
	FD_ZERO(&rfds);
	FD_SET(sv[0], &rfds);
	if (select(sv[0]+1, &rfds, NULL, NULL, NULL) < 0) {
		printf("Error getting go-ahead from server: %s\n", strerror(errno));
		exit(1);
	}
	ret = read(sv[0], buf, 1);
	if (ret != 1 || buf[0] != '1')
		printf("WARNING: server replied with error\n");
out:
	close(sv[0]);
	close(sv[1]);
	cgmanager_disconnect();
}

void cgchown(const char *cg, uid_t uid, gid_t gid)
{
	cgmanager_connect();
	if ( cgmanager_chown_sync(NULL, cgroup_manager, controller, cg, uid, gid) != 0) {
		NihError *nerr;
		nerr = nih_error_get();
		printf("call to cgmanager_move_pid_sync failed: %s\n", nerr->message);
		nih_free(nerr);
		cgmanager_disconnect();
		exit(1);
	}
	cgmanager_disconnect();
}

int execchild(void)
{
	char buf[1];
	create("newchild");
	buf[0] = '1';
	write(101, buf, 1);
	if (read(100, buf, 1) != 1 || buf[0] != '1')
		exit(1);
	printf("moving myself to newchild: I am %d\n", geteuid());
	movepid("newchild", getpid());
	write(101, buf, 1);
	if (read(100, buf, 1) != 1 || buf[0] != '1')
		exit(1);
	exit(0);
}

void do_pipe(void)
{
	if (pipe(tochild) < 0 || pipe(fromchild) < 0) {
		perror("pipe");
		exit(1);
	}
}

int dochild(void *arg)
{
	char buf[1];

	close(tochild[1]);
	close(fromchild[0]);
	close(100); close(101);
	dup2(tochild[0], 100);
	dup2(fromchild[1], 101);
	if (read(tochild[0], buf, 1) != 1 || buf[0] != '1')
		exit(1);
	setgid(0);
	setuid(0);
	execlp(mycmd, "nstest", "child", NULL);
	exit(1);  // notreached
}

pid_t do_clone(void)
{
	long stack_size = 4096;
	int flags;
	void *stack = alloca(stack_size);
	pid_t pid;

	flags = CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUSER | SIGCHLD;
#ifdef __ia64__
	pid = __clone2(dochild, stack, stack_size, flags,  NULL);
#else
	stack += stack_size;
	pid = clone(dochild, stack, flags, NULL);
#endif
	if (pid == -1) {
		perror("clone");
		exit(1);
	}
	/* set up uid map */
	return pid;
}

char *getcg(pid_t pid)
{
	char path[128];
	sprintf(path, "/proc/%d/cgroup", (int)pid);
	FILE *f = fopen(path, "r");
	char *line = NULL, *ret = NULL;
	size_t len = 0;

	if (!f)
		return NULL;

	while (getline(&line, &len, f) != -1) {
		char *p1, *p2;
		p1 = strchr(line, ':');
		if (!p1)
			continue;
		p1++;
		p2 = strchr(p1, ':');
		if (!p2)
			continue;
		*p2 = '\0';
		p2++;
		if (strcmp(p1, "freezer") != 0)
			continue;
		ret = strdup(p2);
		break;
	}
	fclose(f);
	if (line)
		free(line);
	return ret;
}

void strip(char *s)
{
	char *t;
	if (!s || !strlen(s))
		return;
	t = s + strlen(s)-1;
	if (t >= s && *t == '\n')
		*t = '\0';
}

void verify_child_cgroup(pid_t pid)
{
	char *mycg, *childcg, *calccg;
	mycg = getcg(getpid());
	childcg = getcg(pid);
	if (!mycg || !childcg) {
		printf("Failed getting cgroups\n");
		exit(1);
	}
	if (strlen(mycg) == strlen(childcg)) {
		printf("child did not change cg\n");
		printf("I am %d child is %d\n", (int)getpid(), (int)pid);
		exit(1);
	}
	calccg = alloca(strlen(mycg) + 10);
	strip(mycg);
	strip(childcg);
	sprintf(calccg, "%s/newchild", mycg);
	if (strcmp(calccg, childcg) != 0) {
		printf("child is in wrong cg: %s not %s\n", childcg, calccg);
		exit(1);
	}
}

void write_idmap(char *path)
{
	FILE *f = fopen(path, "w");
	if (!f) {
		printf("failed opening idmap file: %m\n");
		exit(1);
	}
	if (fprintf(f, "0 900000 100000\n") < 0) {
		printf("fprintf to uidmap failed: %m\n");
		exit(1);
	}
	if (fclose(f) != 0) {
		printf("fclose of uidmap failed: %m\n");
		exit(1);
	}
}

void setup_uidmap(pid_t pid)
{
	char path[128];
	FILE *f;
	sprintf(path, "/proc/%d/uid_map", (int)pid);
	write_idmap(path);
	sprintf(path, "/proc/%d/gid_map", (int)pid);
	write_idmap(path);
}

int main(int argc, char *argv[])
{
	int ret, status;
	pid_t pid;
	char buf[1];

	if (argc == 2 && strcmp(argv[1], "child") == 0)
		return execchild();

	if (getuid()) {
		printf("Run me as root\n");
		exit(1);
	}

	mycmd = argv[0];
	printf("Creating new cgroup 'newchild'\n");
	create("unstest");
	printf("Moving myself to child cgroup\n");
	movepid("unstest", getpid());
	printf("Chowning child cgroup\n");
	cgchown("", 900000, 90000);
	buf[0] = '1';
	do_pipe();

	printf("Cloning child\n");
	pid = do_clone();
	close(tochild[0]);
	close(fromchild[1]);
	setup_uidmap(pid);

	/* trigger the cgroup create */
	printf("Asking child to exec in new ns and create newchild cgroup\n");
	write(tochild[1], buf, 1);
	if (read(fromchild[0], &buf, 1) != 1 || buf[0] != '1') {
		printf("create test failed\n");
		exit(1);
	}

	/* trigger fork and cgroup move */
	printf("Asking child to fork and move its child into new cgroup\n");
	write(tochild[1], buf, 1);
	if (read(fromchild[0], &buf, 1) != 1 || buf[0] != '1') {
		printf("create test failed\n");
		exit(1);
	}

	/* verify child is in new cgroup */
	verify_child_cgroup(pid);
	write(tochild[1], buf, 1);
	wait(&status);
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		printf("PASS\n");
		exit(0);
	}
	printf("FAIL\n");
	exit(1);
}
