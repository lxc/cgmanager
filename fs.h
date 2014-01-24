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

int setup_cgroup_mounts(void);
bool compute_pid_cgroup(pid_t pid, const char *controller, const char *cgroup, char *path);
bool may_access(pid_t pid, uid_t uid, gid_t gid, const char *path, int mode);
void get_pid_creds(pid_t pid, uid_t *uid, gid_t *gid);
char *file_read_string(void *parent, const char *path);
int file_read_pids(void *parent, const char *path, int32_t **pids);
void get_pid_creds(pid_t pid, uid_t *uid, gid_t *gid);
const char *get_controller_path(const char *controller);
bool hostuid_to_ns(uid_t uid, pid_t pid, uid_t *answer);
bool chown_cgroup_path(const char *path, uid_t uid, gid_t gid, bool all_children);
bool set_value(const char *path, const char *value);
unsigned long read_pid_ns_link(int pid);
unsigned long read_user_ns_link(int pid);
bool realpath_escapes(char *path, char *safety);
bool file_exists(const char *path);
bool dir_exists(const char *path);
