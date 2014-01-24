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
#include <string.h>
#include <ctype.h>
#include <sched.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <sys/param.h>
#include <stdbool.h>
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
#include <nih-dbus/dbus_proxy.h>

#include "fs.h"

extern bool setns_pid_supported, setns_user_supported;
extern unsigned long mypidns, myuserns;

bool get_nih_io_creds(NihIo *io, struct ucred *ucred)
{
	NihIoMessage *msg = nih_io_read_message(NULL, io);
	if (!msg) {
		nih_error("failed reading msg for ucred");
		return false;
	}
	struct cmsghdr *cmsg = msg->control[0];
	if (!cmsg) {
		nih_error("cmsg null");
		return false;
	}
	if (cmsg->cmsg_level != SOL_SOCKET) nih_error("level %d sock %d", cmsg->cmsg_level, SOL_SOCKET);
	if (cmsg->cmsg_level != SOL_SOCKET ||
			cmsg->cmsg_len != CMSG_LEN (sizeof(*ucred)) ||
			cmsg->cmsg_type != SCM_CREDENTIALS) {
		nih_error("non-scm control message");
		return false;
	}
	memcpy(ucred, CMSG_DATA(cmsg), sizeof(*ucred));
	if (ucred->pid == -1)
		return false;
	nih_info("got creds pid %d uid %d", ucred->pid, ucred->uid);
	return true;
}

int send_creds(int sock, struct ucred cred)
{
	struct msghdr msg = { 0 };
	struct iovec iov;
	struct cmsghdr *cmsg;
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

/*
 * Get a pid passed in a SCM_CREDENTIAL over a unix socket
 * @sock: the socket fd.
 * Credentials are invalid of *p == 1.
 * Note - this is a synchronous version.  We use it only in the proxy to wait
 * on the server, since there is no sense not hanging in that case.
 */
void get_scm_creds_sync(int sock, uid_t *u, gid_t *g, pid_t *p)
{
        struct msghdr msg = { 0 };
        struct iovec iov;
        struct cmsghdr *cmsg;
	struct ucred cred;
        char cmsgbuf[CMSG_SPACE(sizeof(cred))];
        char buf[1];
	int ret;
	int optval = 1;

	cred.pid = -1;
	cred.uid = -1;
	cred.gid = -1;

	if (setsockopt(sock, SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
		nih_error("Failed to set passcred: %s", strerror(errno));
		goto out;
	}
	buf[0] = '1';
	if (write(sock, buf, 1) != 1) {
		nih_error("Failed to start write on scm fd: %s", strerror(errno));
		goto out;
	}

        msg.msg_name = NULL;
        msg.msg_namelen = 0;
        msg.msg_control = cmsgbuf;
        msg.msg_controllen = sizeof(cmsgbuf);

        iov.iov_base = buf;
        iov.iov_len = sizeof(buf);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

	// retry logic is not ideal, especially as we are not
	// threaded.  Sleep at most 1 second waiting for the client
	// to send us the scm_cred
	ret = recvmsg(sock, &msg, 0);
	if (ret < 0) {
		nih_error("Failed to receive scm_cred: %s",
			  strerror(errno));
		goto out;
	}

        cmsg = CMSG_FIRSTHDR(&msg);

        if (cmsg && cmsg->cmsg_len == CMSG_LEN(sizeof(struct ucred)) &&
            cmsg->cmsg_level == SOL_SOCKET &&
            cmsg->cmsg_type == SCM_CREDENTIALS) {
		memcpy(&cred, CMSG_DATA(cmsg), sizeof(cred));
        }
out:
	*u = cred.uid;
	*g = cred.gid;
	*p = cred.pid;
        return;
}

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

/*
 * Return true if pid is in my pidns
 * Figure this out by comparing the /proc/pid/ns/pid link names.
 */
bool is_same_pidns(int pid)
{
	if (!setns_pid_supported)
		return false;
	if (read_pid_ns_link(pid) != mypidns)
		return false;
	return true;
}

/*
 * Return true if pid is in my pidns
 * Figure this out by comparing the /proc/pid/ns/user link names.
 */
bool is_same_userns(int pid)
{
	if (!setns_user_supported)
		return false;
	if (read_user_ns_link(pid) != myuserns)
		return false;
	return true;
}

/*
 * May the requestor @r move victim @v to a new cgroup?
 * This is allowed if
 *   . they are the same task
 *   . they are ownedy by the same uid
 *   . @r is root on the host, or
 *   . @v's uid is mapped into @r's where @r is root.
 *
 * XXX do we want to add a restriction that @v must already
 * be under @r's cgroup?
 */
bool may_move_pid(pid_t r, uid_t r_uid, pid_t v)
{
	uid_t v_uid, tmpuid;
	gid_t v_gid;

	if (r == v)
		return true;
	if (r_uid == 0)
		return true;
	get_pid_creds(v, &v_uid, &v_gid);
	if (r_uid == v_uid)
		return true;
	if (hostuid_to_ns(r_uid, r, &tmpuid) && tmpuid == 0
			&& hostuid_to_ns(v_uid, r, &tmpuid))
		return true;
	return false;
}

