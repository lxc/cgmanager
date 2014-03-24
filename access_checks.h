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

bool get_nih_io_creds(void *parent, NihIo *io, struct ucred *ucred);
int send_creds(int sock, struct ucred *cred);
void get_scm_creds_sync(int sock, struct ucred *cred);
bool is_same_pidns(int pid);
bool is_same_userns(int pid);
bool may_move_pid(pid_t r, uid_t r_uid, pid_t v);
int send_pid(int sock, int pid);
