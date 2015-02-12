/* cgmanager
 *
 * Copyright © 2013 Stephane Graber
 * Author: Stephane Graber <stgraber@ubuntu.com>
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

#include <frontend.h>
#include <sys/resource.h>
#include <sys/statvfs.h>
#include <sys/vfs.h>
#include <linux/fs.h>

/*
 * Maximum depth of directories we allow in Create
 * Default is 16.  Figure 4 directories per level of container
 * nesting (/user/1000.user/c2.session/c1), that lets us nest
 * 4 containers deep.
 */
static int maxdepth = 16;

/* GetPidCgroup */
int get_pid_cgroup_main(void *parent, const char *controller,struct ucred p,
			 struct ucred r, struct ucred v, char **output)
{
	char rcgpath[MAXPATHLEN], vcgpath[MAXPATHLEN];

	// Get r's current cgroup in rcgpath
	if (!compute_pid_cgroup(r.pid, controller, "", rcgpath, NULL)) {
		nih_error("%s: Could not determine the requestor's cgroup for %s",
				__func__, controller);
		return -1;
	}

	// Get v's cgroup in vcgpath
	if (!compute_pid_cgroup(v.pid, controller, "", vcgpath, NULL)) {
		nih_error("%s: Could not determine the victim cgroup for %s",
				__func__, controller);
		return -1;
	}

	// Make sure v's cgroup is under r's
	int rlen = strlen(rcgpath);
	if (strncmp(rcgpath, vcgpath, rlen) != 0) {
		nih_error("%s: v (%d)'s cgroup is not below r (%d)'s", __func__,
			v.pid, r.pid);
		return -1;
	}
	if (strlen(vcgpath) == rlen)
		*output = NIH_MUST (nih_strdup(parent, "/") );
	else
		*output = NIH_MUST (nih_strdup(parent, vcgpath + rlen + 1) );

	return 0;
}

/* GetPidCgroupAbs */
int get_pid_cgroup_abs_main(void *parent, const char *controller,struct ucred p,
			 struct ucred r, struct ucred v, char **output)
{
	char rcgpath[MAXPATHLEN], vcgpath[MAXPATHLEN];

	// Get p's current cgroup in rcgpath
	if (!compute_pid_cgroup(p.pid, controller, "", rcgpath, NULL)) {
		nih_error("%s: Could not determine the requestor's cgroup for %s",
				__func__, controller);
		return -1;
	}

	// Get v's cgroup in vcgpath
	if (!compute_pid_cgroup(v.pid, controller, "", vcgpath, NULL)) {
		nih_error("%s: Could not determine the victim cgroup for %s",
				__func__, controller);
		return -1;
	}

	// Make sure v's cgroup is under p's
	int rlen = strlen(rcgpath);
	if (strncmp(rcgpath, vcgpath, rlen) != 0) {
		nih_error("%s: v (%d)'s cgroup is not below p (%d)'s", __func__,
			v.pid, p.pid);
		return -1;
	}
	if (strlen(vcgpath) == rlen)
		*output = NIH_MUST (nih_strdup(parent, "/") );
	else
		*output = NIH_MUST (nih_strdup(parent, vcgpath + rlen) );

	return 0;
}

static bool victim_under_proxy_cgroup(char *rcgpath, pid_t v,
		const char *controller)
{
	char vcgpath[MAXPATHLEN];

	if (!compute_pid_cgroup(v, controller, "", vcgpath, NULL)) {
		nih_error("%s: Could not determine the victim's cgroup for %s",
				__func__, controller);
		return false;
	}
	if (strncmp(vcgpath, rcgpath, strlen(rcgpath)) != 0)
		return false;
	return true;
}

int per_ctrl_move_pid_main(const char *controller, const char *cgroup, struct ucred p,
		struct ucred r, struct ucred v, bool escape)
{
	char rcgpath[MAXPATHLEN], path[MAXPATHLEN];
	FILE *f;
	pid_t query = r.pid;

	// Get r's current cgroup in rcgpath
	if (escape)
		query = p.pid;
	if (!compute_pid_cgroup(query, controller, "", rcgpath, NULL)) {
		nih_error("%s: Could not determine the requestor's cgroup for %s",
                __func__, controller);
		return -1;
	}

	// If the victim is not under proxy's cgroup, refuse
	if (!victim_under_proxy_cgroup(rcgpath, v.pid, controller)) {
		nih_error("%s: victim's cgroup is not under proxy's (p.uid %u)", __func__, p.uid);
		return -1;
	}

	/* rcgpath + / + cgroup + /tasks + \0 */
	if (strlen(rcgpath) + strlen(cgroup) > MAXPATHLEN - 8) {
		nih_error("%s: Path name too long", __func__);
		return -1;
	}
	strcpy(path, rcgpath);
	strncat(path, "/", MAXPATHLEN-1);
	strncat(path, cgroup, MAXPATHLEN-1);
	if (realpath_escapes(path, rcgpath)) {
		nih_error("%s: Invalid path %s", __func__, path);
		return -1;
	}
	// is r allowed to descend under the parent dir?
	if (!may_access(r.pid, r.uid, r.gid, path, O_RDONLY)) {
		nih_error("%s: pid %d (uid %u gid %u) may not read under %s", __func__,
			r.pid, r.uid, r.gid, path);
		return -1;
	}
	// is r allowed to write to tasks file?
	strncat(path, "/tasks", MAXPATHLEN-1);
	if (!may_access(r.pid, r.uid, r.gid, path, O_WRONLY)) {
		nih_error("%s: pid %d (uid %u gid %u) may not write to %s", __func__,
			r.pid, r.uid, r.gid, path);
		return -1;
	}
	f = fopen(path, "w");
	if (!f) {
		nih_error("%s: Failed to open %s", __func__, path);
		return -1;
	}
	if (fprintf(f, "%d\n", v.pid) < 0) {
		fclose(f);
		nih_error("%s: Failed to write %d to %s", __func__, v.pid, path);
		return -1;
	}
	if (fclose(f) != 0) {
		nih_error("%s: Failed to write %d to %s", __func__, v.pid, path);
		return -1;
	}
	nih_info(_("%d moved to %s:%s by %d's request"), v.pid,
		controller, cgroup, r.pid);
	return 0;
}

int do_move_pid_main(const char *controller, const char *cgroup, struct ucred p,
		struct ucred r, struct ucred v, bool escape)
{
	nih_local char *c = NULL;
	char *tok;
	int ret;
	int while_ret = 0;

	if (!sane_cgroup(cgroup)) {
		nih_error("%s: unsafe cgroup", __func__);
		return -1;
	}

	// verify that ucred.pid may move target pid
	if (!may_move_pid(r.pid, r.uid, v.pid)) {
		nih_error("%s: %d may not move %d", __func__, r.pid, v.pid);
		return -1;
	}

	if (strcmp(controller, "all") != 0 && !strchr(controller, ','))
		return per_ctrl_move_pid_main(controller, cgroup, p, r, v, escape);

	if (strcmp(controller, "all") == 0) {
		if (!all_controllers)
			return 0;
		c = NIH_MUST( nih_strdup(NULL, all_controllers) );
	} else {
		c = NIH_MUST( nih_strdup(NULL, controller) );
		do_prune_comounts(c);
	}
	tok = strtok(c, ",");
	while (tok) {
		ret = per_ctrl_move_pid_main(tok, cgroup, p, r, v, escape);

		/* Save error for later (but ignore permission denied, -2),
		   but try to complete rest of moves anyway */
		if (ret != 0 && ret != -2)
			while_ret = -1;

		tok = strtok(NULL, ",");
	}

	return while_ret;
}

int move_pid_main(const char *controller, const char *cgroup, struct ucred p,
		struct ucred r, struct ucred v)
{
	if (cgroup[0] == '/') {
		// We could try to be accomodating, but let's not fool around right now
		nih_error("%s: Bad requested cgroup path: %s", __func__, cgroup);
		return -1;
	}

	return do_move_pid_main(controller, cgroup, p, r, v, false);
}

int move_pid_abs_main(const char *controller, const char *cgroup, struct ucred p,
		struct ucred r, struct ucred v)
{
	return do_move_pid_main(controller, cgroup, p, r, v, true);
}

int do_create_main(const char *controller, const char *cgroup, struct ucred p,
		struct ucred r, int32_t *existed)
{
	int ret, depth;
	char rcgpath[MAXPATHLEN], path[MAXPATHLEN], dirpath[MAXPATHLEN];
	nih_local char *copy = NULL;
	size_t cgroup_len;
	char *p1, *p2, oldp2;

	*existed = 1;
	// Get r's current cgroup in rcgpath
	if (!compute_pid_cgroup(r.pid, controller, "", rcgpath, &depth)) {
		nih_error("%s: Could not determine the requestor's cgroup for %s",
                __func__, controller);
		return -1;
	}

	if (depth > maxdepth) {
		nih_error("%s: Cgroup too deep: %s/%s", __func__, rcgpath, cgroup);
		return -1;
	}

	cgroup_len = strlen(cgroup);

	if (strlen(rcgpath) + cgroup_len > MAXPATHLEN) {
		nih_error("%s: Path name too long", __func__);
		return -1;
	}
	copy = NIH_MUST( nih_strndup(NULL, cgroup, cgroup_len) );

	strcpy(path, rcgpath);
	strcpy(dirpath, rcgpath);
	for (p1=copy; *p1; p1 = p2) {
		*existed = -1;
		for (p2=p1; *p2 && *p2 != '/'; p2++);
		oldp2 = *p2;
		*p2 = '\0';
		if (strcmp(p1, "..") == 0) {
			nih_error("%s: Invalid cgroup path at create: %s", __func__, p1);
			return -1;
		}
		strncat(path, "/", MAXPATHLEN-1);
		strncat(path, p1, MAXPATHLEN-1);
		if (dir_exists(path)) {
			*existed = 1;
			// TODO - properly use execute perms
			if (!may_access(r.pid, r.uid, r.gid, path, O_RDONLY)) {
				nih_error("%s: pid %d (uid %u gid %u) may not look under %s", __func__,
					r.pid, r.uid, r.gid, path);
				return -2;
			}
			goto next;
		}
		if (!may_access(r.pid, r.uid, r.gid, dirpath, O_RDWR)) {
			nih_error("%s: pid %d (uid %u gid %u) may not create under %s", __func__,
				r.pid, r.uid, r.gid, dirpath);
			return -2;
		}
		ret = mkdir(path, 0755);
		if (ret < 0) {  // Should we ignore EEXIST?  Ok, but don't chown.
			if (errno == EEXIST) {
				*existed = 1;
				goto next;
			}
			nih_error("%s: failed to create %s", __func__, path);
			return -2;
		}
		if (!chown_cgroup_path(path, r.uid, r.gid, true)) {
			nih_error("%s: Failed to change ownership on %s to %u:%u", __func__,
				path, r.uid, r.gid);
			rmdir(path);
			return -1;
		}
		*existed = -1;
next:
		strncat(dirpath, "/", MAXPATHLEN-1);
		strncat(dirpath, p1, MAXPATHLEN-1);
		*p2 = oldp2;
		if (*p2)
			p2++;
	}


	nih_info(_("Created %s for %d (%u:%u)"), path, r.pid,
		 r.uid, r.gid);
	return 0;
}

int create_main(const char *controller, const char *cgroup, struct ucred p,
		struct ucred r, int32_t *existed)
{
	nih_local char *c = NULL;
	char *tok;
	int ret;

	*existed = -1;
	if (!cgroup || ! *cgroup)  // nothing to do
		return 0;

	if (!sane_cgroup(cgroup)) {
		nih_error("%s: unsafe cgroup", __func__);
		return -1;
	}

	if (strcmp(controller, "all") != 0 && !strchr(controller, ','))
		return do_create_main(controller, cgroup, p, r, existed);

	if (strcmp(controller, "all") == 0) {
		if (!all_controllers)
			return 0;
		c = NIH_MUST( nih_strdup(NULL, all_controllers) );
	} else {
		c = NIH_MUST( nih_strdup(NULL, controller) );
		do_prune_comounts(c);
	}
	tok = strtok(c, ",");
	while (tok) {
		int32_t e = 1;
		ret = do_create_main(tok, cgroup, p, r, &e);
		if (ret == -2)  // permission denied - ignore for group requests
			goto next;
		if (ret != 0)
			return -1;
		if (e == 1)
			*existed = 1;
next:
		tok = strtok(NULL, ",");
	}

	return 0;
}

int do_chown_main(const char *controller, const char *cgroup, struct ucred p,
		struct ucred r, struct ucred v)
{
	char rcgpath[MAXPATHLEN];
	nih_local char *path = NULL;

	// Get r's current cgroup in rcgpath
	if (!compute_pid_cgroup(r.pid, controller, "", rcgpath, NULL)) {
		nih_error("%s: Could not determine the requestor's cgroup for %s",
                __func__, controller);
		return -1;
	}
	/* rcgpath + / + cgroup + \0 */
	if (strlen(rcgpath) + strlen(cgroup) > MAXPATHLEN+2) {
		nih_error("%s: Path name too long", __func__);
		return -1;
	}
	path = NIH_MUST( nih_sprintf(NULL, "%s/%s", rcgpath, cgroup) );
	if (realpath_escapes(path, rcgpath)) {
		nih_error("%s: Invalid path %s", __func__, path);
		return -1;
	}
	// is r allowed to descend under the parent dir?
	if (!may_access(r.pid, r.uid, r.gid, path, O_RDONLY)) {
		nih_error("%s: pid %d (uid %u gid %u) may not read under %s", __func__,
			r.pid, r.uid, r.gid, path);
		return -2;
	}

	// does r have privilege over the cgroup dir?
	if (!may_access(r.pid, r.uid, r.gid, path, O_RDWR)) {
		nih_error("%s: Pid %d may not chown %s\n", __func__, r.pid, path);
		return -2;
	}

	// go ahead and chown it.
	if (!chown_cgroup_path(path, v.uid, v.gid, false)) {
		nih_error("%s: Failed to change ownership on %s to %u:%u", __func__,
			path, v.uid, v.gid);
		return -2;
	}

	return 0;
}

int chown_main(const char *controller, const char *cgroup, struct ucred p,
		struct ucred r, struct ucred v)
{
	uid_t uid;
	nih_local char *c = NULL;
	char *tok;
	int ret;

	/* If caller is not root in his userns, then he can't chown, as
	 * that requires privilege over two uids */
	if (r.uid) {
		if (!hostuid_to_ns(r.uid, r.pid, &uid) || uid != 0) {
			nih_error("%s: Chown requested by non-root uid %u", __func__, r.uid);
			return -1;
		}
	}

	if (!sane_cgroup(cgroup)) {
		nih_error("%s: unsafe cgroup", __func__);
		return -1;
	}

	if (strcmp(controller, "all") != 0 && !strchr(controller, ','))
		return do_chown_main(controller, cgroup, p, r, v);

	if (strcmp(controller, "all") == 0) {
		if (!all_controllers)
			return 0;
		c = NIH_MUST( nih_strdup(NULL, all_controllers) );
	} else {
		c = NIH_MUST( nih_strdup(NULL, controller) );
		do_prune_comounts(c);
	}
	tok = strtok(c, ",");
	while (tok) {
		ret = do_chown_main(tok, cgroup, p, r, v);
		if (ret == -2)  // permission denied - ignore for group requests
			goto next;
		if (ret != 0)
			return -1;
next:
		tok = strtok(NULL, ",");
	}

	return 0;
}

int do_chmod_main(const char *controller, const char *cgroup, const char *file,
		struct ucred p, struct ucred r, int mode)
{
	char rcgpath[MAXPATHLEN];
	nih_local char *path = NULL;

	// Get r's current cgroup in rcgpath
	if (!compute_pid_cgroup(r.pid, controller, "", rcgpath, NULL)) {
		nih_error("%s: Could not determine the requestor's cgroup for %s",
                __func__, controller);
		return -1;
	}

	path = NIH_MUST( nih_sprintf(NULL, "%s/%s", rcgpath, cgroup) );
	if (file && strlen(file))
		NIH_MUST( nih_strcat_sprintf(&path, NULL, "/%s", file) );
	if (realpath_escapes(path, rcgpath)) {
		nih_error("%s: Invalid path %s", __func__, path);
		return -1;
	}
	// is r allowed to descend under the parent dir?
	if (!may_access(r.pid, r.uid, r.gid, path, O_RDONLY)) {
		nih_error("%s: pid %d (uid %u gid %u) may not read under %s", __func__,
			r.pid, r.uid, r.gid, path);
		return -2;
	}

	// does r have privilege over the cgroup dir?
	if (!may_access(r.pid, r.uid, r.gid, path, O_RDWR)) {
		nih_error("%s: Pid %d may not chmod %s\n", __func__, r.pid, path);
		return -2;
	}

	// go ahead and chmod it.
	if (!chmod_cgroup_path(path, mode)) {
		nih_error("%s: Failed to change mode on %s to %d", __func__,
			path, mode);
		return -2;
	}

	return 0;
}

int chmod_main(const char *controller, const char *cgroup, const char *file,
		struct ucred p, struct ucred r, int mode)
{
	nih_local char *c = NULL;
	char *tok;
	int ret;

	if (!sane_cgroup(cgroup)) {
		nih_error("%s: unsafe cgroup", __func__);
		return -1;
	}

	if (file && ( strchr(file, '/') || strchr(file, '\\')) ) {
		nih_error("%s: invalid file", __func__);
		return -1;
	}

	if (strcmp(controller, "all") != 0 && !strchr(controller, ','))
		return do_chmod_main(controller, cgroup, file, p, r, mode);

	if (strcmp(controller, "all") == 0) {
		if (!all_controllers)
			return 0;
		c = NIH_MUST( nih_strdup(NULL, all_controllers) );
	} else {
		c = NIH_MUST( nih_strdup(NULL, controller) );
		do_prune_comounts(c);
	}
	tok = strtok(c, ",");
	while (tok) {
		ret = do_chmod_main(tok, cgroup, file, p, r, mode);
		if (ret == -2)  // permission denied - ignore for group requests
			goto next;
		if (ret != 0)
			return -1;
next:
		tok = strtok(NULL, ",");
	}

	return 0;
}

int get_value_main(void *parent, const char *controller, const char *cgroup,
		const char *key, struct ucred p, struct ucred r, char **value)
{
	char path[MAXPATHLEN];

	if (!sane_cgroup(cgroup)) {
		nih_error("%s: unsafe cgroup", __func__);
		return -1;
	}

	if (!compute_pid_cgroup(r.pid, controller, cgroup, path, NULL)) {
		nih_error("%s: Could not determine the requested cgroup (%s:%s)",
                __func__, controller, cgroup);
		return -1;
	}

	/* Check access rights to the cgroup directory */
	if (!may_access(r.pid, r.uid, r.gid, path, O_RDONLY)) {
		nih_error("%s: Pid %d may not access %s\n", __func__, r.pid, path);
		return -1;
	}

	if (!path_is_under_taskcg(p.pid, controller, path)) {
		nih_error("%s: target cgroup is not below r (%d)'s", __func__,
			r.pid);
		return -1;
	}

	/* append the filename */
	if (strlen(path) + strlen(key) + 2 > MAXPATHLEN) {
		nih_error("%s: filename too long for cgroup %s key %s", __func__, path, key);
		return -1;
	}

	strncat(path, "/", MAXPATHLEN-1);
	strncat(path, key, MAXPATHLEN-1);

	/* Check access rights to the file itself */
	if (!may_access(r.pid, r.uid, r.gid, path, O_RDONLY)) {
		nih_error("%s: Pid %d may not access %s\n", __func__, r.pid, path);
		return -1;
	}

	/* read and return the value */
	*value = file_read_string(parent, path);
	if (!*value) {
		nih_error("%s: Failed to read value from %s", __func__, path);
		return -1;
	}

	nih_info(_("Sending to client: %s"), *value);
	return 0;
}

int set_value_main(const char *controller, const char *cgroup,
		const char *key, const char *value, struct ucred p,
		struct ucred r)

{
	char path[MAXPATHLEN];

	if (!sane_cgroup(cgroup)) {
		nih_error("%s: unsafe cgroup", __func__);
		return -1;
	}

	if (!compute_pid_cgroup(r.pid, controller, cgroup, path, NULL)) {
		nih_error("%s: Could not determine the requested cgroup (%s:%s)",
                __func__, controller, cgroup);
		return -1;
	}

	if (!path_is_under_taskcg(p.pid, controller, path)) {
		nih_error("%s: target cgroup is not below r (%d)'s", __func__,
			r.pid);
		return -1;
	}

	/* Check access rights to the cgroup directory */
	if (!may_access(r.pid, r.uid, r.gid, path, O_RDONLY)) {
		nih_error("%s: Pid %d may not access %s\n", __func__, r.pid, path);
		return -1;
	}

	/* append the filename */
	if (strlen(path) + strlen(key) + 2 > MAXPATHLEN) {
		nih_error("%s: filename too long for cgroup %s key %s", __func__, path, key);
		return -1;
	}

	strncat(path, "/", MAXPATHLEN-1);
	strncat(path, key, MAXPATHLEN-1);

	/* Check access rights to the file itself */
	if (!may_access(r.pid, r.uid, r.gid, path, O_WRONLY)) {
		nih_error("%s: Pid %d may not access %s\n", __func__, r.pid, path);
		return -1;
	}

	/* read and return the value */
	if (!set_value(path, value)) {
		nih_error("%s: Failed to set value %s to %s", __func__, path, value);
		return -1;
	}

	return 0;
}

/*
 * Refuse any '..', and consolidate any '//'
 */
static bool normalize_path(char *path)
{
	if (strstr(path, ".."))
		return false;
	while ((path = strstr(path, "//")) != NULL) {
		char *p2 = path+1;
		while (*p2 == '/')
			p2++;
		memmove(path, p2, strlen(p2)+1);
		path++;
	}
	return true;
}

/*
 * Recursively delete a cgroup.
 * Cgroup files can't be deleted, but are cleaned up when you remove the
 * containing directory.  A directory cannot be removed until all its
 * children are removed, and can't be removed if any tasks remain.
 *
 * We allow any task which may write under /a/b to delete any cgroups
 * under that, even if, say, it technically is not allowed to remove
 * /a/b/c/d/.
 */
static int recursive_rmdir(char *path)
{
	struct dirent dirent, *direntp;
	DIR *dir;
	int failed = 0;

	dir = opendir(path);
	if (!dir) {
		nih_error("%s: Failed to open dir %s for recursive deletion", __func__, path);
		return -1;
	}

	while (!readdir_r(dir, &dirent, &direntp)) {
		struct stat mystat;
		nih_local char *pathname = NULL;
		int rc;

		if (!direntp)
			break;
		if (!strcmp(direntp->d_name, ".") ||
		    !strcmp(direntp->d_name, ".."))
			continue;
		pathname = NIH_MUST( nih_sprintf(NULL, "%s/%s", path, direntp->d_name) );
		rc = lstat(pathname, &mystat);
		if (rc) {
			failed = 1;
			continue;
		}
		if (S_ISDIR(mystat.st_mode)) {
			if (recursive_rmdir(pathname) < 0)
				failed = 1;
		}
	}

	if (closedir(dir) < 0)
		failed = 1;
	if (rmdir(path) < 0)
		failed = 1;

	return failed ? -1 : 0;
}

int do_remove_main(const char *controller, const char *cgroup, struct ucred p,
		struct ucred r, int recursive, int32_t *existed)
{
	char rcgpath[MAXPATHLEN];
	size_t cgroup_len;
	nih_local char *working = NULL, *copy = NULL, *wcgroup = NULL;
	char *p1;

	*existed = 1;
	// Get r's current cgroup in rcgpath
	if (!compute_pid_cgroup(r.pid, controller, "", rcgpath, NULL)) {
		nih_error("%s: Could not determine the requestor's cgroup for %s",
                __func__, controller);
		return -1;
	}

	cgroup_len = strlen(cgroup);

	if (strlen(rcgpath) + cgroup_len > MAXPATHLEN) {
		nih_error("%s: Path name too long", __func__);
		return -1;
	}

	wcgroup = NIH_MUST( nih_strdup(NULL, cgroup) );
	if (!normalize_path(wcgroup))
		return -1;

	working = NIH_MUST( nih_strdup(NULL, rcgpath) );
	NIH_MUST( nih_strcat(&working, NULL, "/") );
	NIH_MUST( nih_strcat(&working, NULL, wcgroup) );

	if (!dir_exists(working)) {
		*existed = -1;
		return 0;
	}
	// must have write access to the parent dir
	copy = NIH_MUST( nih_strdup(NULL, working) );
	if (!(p1 = strrchr(copy, '/')))
		return -1;
	*p1 = '\0';
	if (!may_access(r.pid, r.uid, r.gid, copy, O_WRONLY)) {
		nih_error("%s: pid %d (%u:%u) may not remove %s", __func__,
			r.pid, r.uid, r.gid, copy);
		return -2;
	}

	if (!recursive) {
		if (rmdir(working) < 0) {
			nih_error("%s: Failed to remove %s: %s", __func__, working, strerror(errno));
			return errno == EPERM ? -2 : -1;
		}
	} else if (recursive_rmdir(working) < 0)
			return -1;

	nih_info(_("Removed %s for %d (%u:%u)"), working, r.pid,
		 r.uid, r.gid);
	return 0;
}

int remove_main(const char *controller, const char *cgroup, struct ucred p,
		struct ucred r, int recursive, int32_t *existed)
{
	nih_local char *c = NULL;
	char *tok;
	int ret;

	*existed = 1;
	if (!sane_cgroup(cgroup)) {
		nih_error("%s: unsafe cgroup", __func__);
		return -1;
	}

	if (strcmp(controller, "all") != 0 && !strchr(controller, ','))
		return do_remove_main(controller, cgroup, p, r, recursive, existed);

	if (strcmp(controller, "all") == 0) {
		if (!all_controllers)
			return 0;
		c = NIH_MUST( nih_strdup(NULL, all_controllers) );
	} else {
		c = NIH_MUST( nih_strdup(NULL, controller) );
		do_prune_comounts(c);
	}
	tok = strtok(c, ",");
	while (tok) {
		int32_t e = 1;
		ret = do_remove_main(tok, cgroup, p, r, recursive, &e);
		if (ret == -2)  // permission denied - ignore for group requests
			goto next;
		if (ret != 0)
			return -1;
		if (!e)
			*existed = 0;
next:
		tok = strtok(NULL, ",");
	}

	return 0;
}

int get_tasks_main(void *parent, const char *controller, const char *cgroup,
			struct ucred p, struct ucred r, int32_t **pids)
{
	char path[MAXPATHLEN];
	const char *key = "tasks";
	int alloced_pids = 0, nrpids = 0;

	if (!sane_cgroup(cgroup)) {
		nih_error("%s: unsafe cgroup", __func__);
		return -1;
	}

	if (!compute_pid_cgroup(r.pid, controller, cgroup, path, NULL)) {
		nih_error("%s: Could not determine the requested cgroup (%s:%s)",
                __func__, controller, cgroup);
		return -1;
	}

	if (!path_is_under_taskcg(p.pid, controller, path)) {
		nih_error("%s: target cgroup is not below r (%d)'s", __func__,
			r.pid);
		return -1;
	}

	/* Check access rights to the cgroup directory */
	if (!may_access(r.pid, r.uid, r.gid, path, O_RDONLY)) {
		nih_error("%s: Pid %d may not access %s\n", __func__, r.pid, path);
		return -1;
	}

	/* append the filename */
	if (strlen(path) + strlen(key) + 2 > MAXPATHLEN) {
		nih_error("%s: filename too long for cgroup %s key %s", __func__, path, key);
		return -1;
	}

	strncat(path, "/", MAXPATHLEN-1);
	strncat(path, key, MAXPATHLEN-1);

	*pids = NULL;
	if (file_read_pids(parent, path, pids, &alloced_pids, &nrpids) < 0) {
		if (*pids)
			nih_free(*pids);
		return -1;
	}
	return nrpids;
}

int do_collect_tasks(void *parent, char **path, int32_t **pids,
			int *alloced_pids, int *nrpids)
{
	struct dirent dirent, *direntp;
	DIR *dir;
	const char *key = "tasks";

	dir = opendir(*path);
	if (!dir) {
		nih_warn("%s: Failed to open dir %s for recursive deletion", __func__, *path);
		return -2;
	}

	while (!readdir_r(dir, &dirent, &direntp)) {
		struct stat mystat;
		nih_local char *childname = NULL;
		int rc;

		if (!direntp)
			break;
		if (!strcmp(direntp->d_name, ".") ||
		    !strcmp(direntp->d_name, ".."))
			continue;
		childname = NIH_MUST( nih_sprintf(NULL, "%s/%s", *path, direntp->d_name) );
		rc = lstat(childname, &mystat);
		if (rc)
			continue;
		if (S_ISDIR(mystat.st_mode))
			if (do_collect_tasks(parent, &childname, pids,
						alloced_pids, nrpids) == -1)
				nih_info("%s: error descending subdirs", __func__);
	}

	closedir(dir);

	/* Get tasks for this directory */
	NIH_MUST( nih_strcat_sprintf(path, NULL, "/%s", key) );

	return file_read_pids(parent, *path, pids, alloced_pids, nrpids);
}

int collect_tasks(void *parent, const char *controller, const char *cgroup,
		struct ucred p, struct ucred r, int32_t **pids,
		int *alloced_pids, int *nrpids)
{
	char path[MAXPATHLEN];
	nih_local char *rpath = NULL;

	if (!sane_cgroup(cgroup)) {
		nih_error("%s: unsafe cgroup", __func__);
		return -1;
	}

	if (!compute_pid_cgroup(r.pid, controller, cgroup, path, NULL)) {
		nih_error("%s: Could not determine the requested cgroup (%s:%s)",
                __func__, controller, cgroup);
		return -2;
	}

	if (!path_is_under_taskcg(p.pid, controller, path)) {
		nih_error("%s: target cgroup is not below r (%d)'s", __func__,
			r.pid);
		return -1;
	}

	/* Check access rights to the cgroup directory */
	if (!may_access(r.pid, r.uid, r.gid, path, O_RDONLY)) {
		nih_error("%s: Pid %d may not access %s\n", __func__, r.pid, path);
		return -2;
	}

	rpath = NIH_MUST( nih_strdup(NULL, path) );
	return do_collect_tasks(parent, &rpath, pids, alloced_pids, nrpids);
}

int get_tasks_recursive_main(void *parent, const char *controller,
		const char *cgroup, struct ucred p, struct ucred r, int32_t **pids)
{
	nih_local char *c = NULL;
	char *tok;
	int ret;
	int alloced_pids = 0, nrpids = 0;

	if (!sane_cgroup(cgroup)) {
		nih_error("%s: unsafe cgroup", __func__);
		return -1;
	}

	*pids = NULL;

	if (strcmp(controller, "all") != 0 && !strchr(controller, ',')) {
		if (collect_tasks(parent, controller, cgroup, p, r, pids,
				&alloced_pids, &nrpids) < 0) {
			if (*pids)
				nih_free(*pids);
			return -1;
		}
		return nrpids;
	}

	if (strcmp(controller, "all") == 0) {
		if (!all_controllers)
			return 0;
		c = NIH_MUST( nih_strdup(NULL, all_controllers) );
	} else {
		c = NIH_MUST( nih_strdup(NULL, controller) );
		do_prune_comounts(c);
	}
	tok = strtok(c, ",");
	while (tok) {
		ret = collect_tasks(parent, tok, cgroup, p, r, pids,
				&alloced_pids, &nrpids);
		if (ret == -2)  // permission denied - ignore
			goto next;
		if (ret != 0) {
			if (*pids)
				nih_free(*pids);
			return -1;
		}
next:
		tok = strtok(NULL, ",");
	}

	return nrpids;
}

int list_children_main(void *parent, const char *controller, const char *cgroup,
			struct ucred p, struct ucred r, char ***output)
{
	char path[MAXPATHLEN];

	*output = NULL;
	if (!sane_cgroup(cgroup)) {
		nih_error("%s: unsafe cgroup", __func__);
		return -1;
	}

	if (!compute_pid_cgroup(r.pid, controller, cgroup, path, NULL)) {
		nih_error("%s: Could not determine the requested cgroup (%s:%s)",
                __func__, controller, cgroup);
		return -1;
	}

	if (!path_is_under_taskcg(p.pid, controller, path)) {
		nih_error("%s: target cgroup is not below r (%d)'s", __func__,
			r.pid);
		return -1;
	}

	/* Check access rights to the cgroup directory */
	if (!may_access(r.pid, r.uid, r.gid, path, O_RDONLY)) {
		nih_error("%s: Pid %d may not access %s\n", __func__, r.pid, path);
		return -1;
	}

	return get_directory_children(parent, path, output);
}

int do_remove_on_empty_main(const char *controller, const char *cgroup,
		struct ucred p, struct ucred r)
{
	char rcgpath[MAXPATHLEN];
	size_t cgroup_len;
	nih_local char *working = NULL, *wcgroup = NULL;

	if (was_premounted(controller)) {
		nih_error("remove-on-empty request for pre-mounted controller");
		return -2;
	}

	// Get r's current cgroup in rcgpath
	if (!compute_pid_cgroup(r.pid, controller, "", rcgpath, NULL)) {
		nih_error("%s: Could not determine the requestor's cgroup for %s",
                __func__, controller);
		return -1;
	}

	cgroup_len = strlen(cgroup);

	if (strlen(rcgpath) + cgroup_len > MAXPATHLEN) {
		nih_error("%s: Path name too long", __func__);
		return -1;
	}

	wcgroup = NIH_MUST( nih_strdup(NULL, cgroup) );
	if (!normalize_path(wcgroup))
		return -1;

	working = NIH_MUST( nih_strdup(NULL, rcgpath) );
	NIH_MUST( nih_strcat(&working, NULL, "/") );
	NIH_MUST( nih_strcat(&working, NULL, wcgroup) );

	if (!dir_exists(working)) {
		return -1;
	}
	// must have write access
	if (!may_access(r.pid, r.uid, r.gid, working, O_WRONLY)) {
		nih_error("%s: pid %d (%u:%u) may not remove %s", __func__,
			r.pid, r.uid, r.gid, working);
		return -1;
	}

	NIH_MUST( nih_strcat(&working, NULL, "/notify_on_release") );

	if (!set_value_trusted(working, "1\n")) {
		nih_error("Failed to set remove_on_empty for %s:%s", controller, working);
		return -1;
	}

	return 0;
}

int remove_on_empty_main(const char *controller, const char *cgroup,
		struct ucred p, struct ucred r)
{
	nih_local char *c = NULL;
	char *tok;
	int ret;

	if (!sane_cgroup(cgroup)) {
		nih_error("%s: unsafe cgroup", __func__);
		return -1;
	}

	if (strcmp(controller, "all") != 0 && !strchr(controller, ','))
		return do_remove_on_empty_main(controller, cgroup, p, r);

	if (strcmp(controller, "all") == 0) {
		if (!all_controllers)
			return 0;
		c = NIH_MUST( nih_strdup(NULL, all_controllers) );
	} else {
		c = NIH_MUST( nih_strdup(NULL, controller) );
		do_prune_comounts(c);
	}
	tok = strtok(c, ",");
	while (tok) {
		ret = do_remove_on_empty_main(tok, cgroup, p, r);
		if (ret == -2)  // pre-mounted, autoremove not an option, ignore
			goto next;
		if (ret != 0)
			return -1;
next:
		tok = strtok(NULL, ",");
	}

	return 0;
}

void do_recursive_prune(char *path, bool autoremove)
{
	nih_local char *releasefile = NULL;
	struct dirent dirent, *direntp;
	DIR *dir;

	if (!autoremove)
		goto remove;

	releasefile = NIH_MUST( nih_strdup(NULL, path) );
	NIH_MUST( nih_strcat(&releasefile, NULL, "/notify_on_release") );

	if (!set_value_trusted(releasefile, "1\n"))
		nih_info("Failed to set remove-on-empty for %s\n", path);

remove:
	dir = opendir(path);
	if (!dir) {
		nih_warn("%s: Failed to open dir %s for recursive deletion", __func__, path);
		return;
	}

	while (!readdir_r(dir, &dirent, &direntp)) {
		struct stat mystat;
		int rc;
		nih_local char *pathname = NULL;

		if (!direntp)
			break;
		if (!strcmp(direntp->d_name, ".") ||
		    !strcmp(direntp->d_name, ".."))
			continue;
		pathname = NIH_MUST( nih_sprintf(NULL, "%s/%s", path, direntp->d_name) );
		rc = lstat(pathname, &mystat);
		if (rc)
			continue;
		if (S_ISDIR(mystat.st_mode))
			do_recursive_prune(pathname, autoremove);
	}

	closedir(dir);
	rmdir(path);
}

int do_prune_main(const char *controller, const char *cgroup,
		struct ucred p, struct ucred r)
{
	char rcgpath[MAXPATHLEN];
	size_t cgroup_len;
	nih_local char *working = NULL, *wcgroup = NULL;

	// Get r's current cgroup in rcgpath
	if (!compute_pid_cgroup(r.pid, controller, "", rcgpath, NULL)) {
		nih_error("%s: Could not determine the requestor's cgroup for %s",
                __func__, controller);
		return -1;
	}

	cgroup_len = strlen(cgroup);

	if (strlen(rcgpath) + cgroup_len > MAXPATHLEN) {
		nih_error("%s: Path name too long", __func__);
		return -1;
	}

	wcgroup = NIH_MUST( nih_strdup(NULL, cgroup) );
	if (!normalize_path(wcgroup))
		return -1;

	working = NIH_MUST( nih_strdup(NULL, rcgpath) );
	NIH_MUST( nih_strcat(&working, NULL, "/") );
	NIH_MUST( nih_strcat(&working, NULL, wcgroup) );

	if (!dir_exists(working)) {
		return -1;
	}
	// must have write access
	if (!may_access(r.pid, r.uid, r.gid, working, O_WRONLY)) {
		nih_error("%s: pid %d (%u:%u) may not remove %s", __func__,
			r.pid, r.uid, r.gid, working);
		return -1;
	}

	do_recursive_prune(working, !was_premounted(controller));

	return 0;
}

int prune_main(const char *controller, const char *cgroup,
		struct ucred p, struct ucred r)
{
	nih_local char *c = NULL;
	char *tok;
	int ret;

	if (!sane_cgroup(cgroup)) {
		nih_error("%s: unsafe cgroup", __func__);
		return -1;
	}

	if (strcmp(controller, "all") != 0 && !strchr(controller, ','))
		return do_prune_main(controller, cgroup, p, r);

	if (strcmp(controller, "all") == 0) {
		if (!all_controllers)
			return 0;
		c = NIH_MUST( nih_strdup(NULL, all_controllers) );
	} else {
		c = NIH_MUST( nih_strdup(NULL, controller) );
		do_prune_comounts(c);
	}
	tok = strtok(c, ",");
	while (tok) {
		ret = do_prune_main(tok, cgroup, p, r);
		if (ret != 0)
			nih_warn("do_prune_main for %s: %s failed", tok, cgroup);
		tok = strtok(NULL, ",");
	}

	return 0;
}

int list_controllers_main(void *parent, char ***output)
{
	*output = NULL;

	do_list_controllers(parent, output);

	return 0;
}

int list_keys_main(void *parent, const char *controller, const char *cgroup,
			struct ucred p, struct ucred r,
			struct keys_return_type ***output)
{
	char path[MAXPATHLEN];
	int nrkeys;

	*output = NULL;
	if (!sane_cgroup(cgroup)) {
		nih_error("%s: unsafe cgroup", __func__);
		return -1;
	}

	if (!compute_pid_cgroup(r.pid, controller, cgroup, path, NULL)) {
		nih_error("%s: Could not determine the requested cgroup (%s:%s)",
                __func__, controller, cgroup);
		return -1;
	}

	/* Check access rights to the cgroup directory */
	if (!may_access(r.pid, r.uid, r.gid, path, O_RDONLY)) {
		nih_error("%s: Pid %d may not access %s\n", __func__, r.pid, path);
		return -1;
	}

	nrkeys = get_directory_contents(parent, path, output);

	if (nrkeys <= 0)
		return nrkeys;

	/* convert uid/gid into r's namespace */
	convert_directory_contents(*output, r);

	return nrkeys;
}

char *extra_cgroup_mounts;
char *skip_cgroup_mounts;

static int
skip_mounts_set (NihOption *option, const char *arg)
{
	skip_cgroup_mounts = NIH_MUST( strdup(arg) );

	return 0;
}

static int
extra_mounts_set (NihOption *option, const char *arg)
{
	extra_cgroup_mounts = NIH_MUST( strdup(arg) );

	return 0;
}

/**
 * options:
 *
 * Command-line options accepted by this program.
 **/
static NihOption options[] = {
	{ 0, "max-depth", N_("Maximum cgroup depth"),
		NULL, NULL, &maxdepth, NULL },
	{ 'M', "skip", N_("Subsystems to not mount"),
		NULL, "subsystems to mount", NULL, skip_mounts_set },
	{ 'm', "mount", N_("Extra subsystems to mount"),
		NULL, "subsystems to mount", NULL, extra_mounts_set },
	{ 0, "daemon", N_("Detach and run in the background"),
		NULL, NULL, &daemonise, NULL },
	{ 0, "sigstop", N_("Raise SIGSTOP when ready"),
		NULL, NULL, &sigstop, NULL },

	NIH_OPTION_LAST
};

static inline int mkdir_cgmanager_dir(void)
{
	if (mkdir(CGMANAGER_DIR, 0755) == -1 && errno != EEXIST) {
		nih_error("%s: Could not create %s", __func__, CGMANAGER_DIR);
		return false;
	}
	return true;
}

static bool daemon_running(void)
{
	DBusConnection *server_conn;
	NihError *err;

	server_conn = nih_dbus_connect(CGMANAGER_DBUS_PATH, NULL);
	if (server_conn) {
		dbus_connection_unref (server_conn);
		return true;
	}
	err = nih_error_get();
	nih_free(err);
	return false;
}

static bool dir_is_sysfs(const char *path)
{
	struct statfs sb;

	if (statfs(path, &sb) < 0)
		// was not yet a mountpoint
		return true;

	return sb.f_type == 0x62656572;
}

static void mount_tmpfs_at(const char *path)
{
	if (mount("cgroup", path, "tmpfs", 0, "size=10000,mode=0755") < 0) {
		nih_error("Failed to mount tmpfs at %s: %m", path);
		exit(1);
	}
	nih_debug("Mounted tmpfs onto %s", path);
}

static bool is_ro_mount(const char *path)
{
	struct statvfs sb;

	if (statvfs(path, &sb) < 0) {
		nih_error("statvfs failed on %s: %m", path);
		exit(1);
	}

	return sb.f_flag & MS_RDONLY;
}

static void turn_mount_rw(const char *path)
{
	if (mount("", path, "cgroup", MS_REMOUNT, NULL) < 0) {
		nih_error("Failed to turn %s mount readonly: %m", path);
		exit(1);
	}
	nih_debug("Turned %s from ro->rw", path);
}

/*
 * We may decide to make the socket path customizable.  For now
 * just assume it is in /sys/fs/cgroup/ which has some special
 * consequences
 */
static bool setup_cgroup_dir(void)
{
	if (!dir_exists(CGDIR)) {
		nih_debug(CGDIR " does not exist");
		return false;
	}

	if (daemon_running()) {
		nih_error("%s: cgmanager is already running", __func__);
		return false;
	}

	if (file_exists(CGMANAGER_SOCK)) {
		if (unlink(CGMANAGER_SOCK) < 0) {
			nih_error("%s: failed to delete stale cgmanager socket", __func__);
			return false;
		}
	}

	if (dir_is_sysfs(CGDIR))
		mount_tmpfs_at(CGDIR);
	else if (is_ro_mount(CGDIR))
		turn_mount_rw(CGDIR);

	return mkdir_cgmanager_dir();
}

int
main (int argc, char *argv[])
{
	char **		args;
	int		ret;
	DBusServer *	server;
	struct stat sb;
	struct rlimit newrlimit;

	nih_main_init (argv[0]);

	nih_option_set_synopsis (_("Control group manager"));
	nih_option_set_help (_("The cgroup manager daemon"));

	args = nih_option_parser (NULL, argc, argv, options, FALSE);
	if (! args)
		exit (1);

	if (!setup_cgroup_dir()) {
		nih_fatal("Failed to set up cgmanager socket");
		exit(1);
	}

	/* Setup the DBus server */
	server = nih_dbus_server (CGMANAGER_DBUS_PATH, client_connect,
				  client_disconnect);
	nih_assert (server != NULL);

	if (!setup_base_run_path()) {
		nih_fatal("Error setting up base cgroup path");
		return -1;
	}

	if (collect_subsystems(extra_cgroup_mounts, skip_cgroup_mounts) < 0)
	{
		nih_fatal("failed to collect cgroup subsystems");
		exit(1);
	}

	if (!create_agent_symlinks()) {
		nih_fatal("Error creating release agent symlinks");
		exit(1);
	}

	if (setup_cgroup_mounts() < 0) {
		nih_fatal ("Failed to set up cgroup mounts");
		exit(1);
	}

	if (!move_self_to_root()) {
		nih_fatal ("Failed to move self to root cgroup");
		exit(1);
	}

	if (stat("/proc/self/ns/pid", &sb) == 0) {
		mypidns = read_pid_ns_link(getpid());
		setns_pid_supported = true;
	}

	if (stat("/proc/self/ns/user", &sb) == 0) {
		myuserns = read_user_ns_link(getpid());
		setns_user_supported = true;
	}

	newrlimit.rlim_cur = 10000;
	newrlimit.rlim_max = 10000;
	if (setrlimit(RLIMIT_NOFILE, &newrlimit) < 0)
		nih_warn("Failed to increase open file limit: %s",
			strerror(errno));

	/* Become daemon */
	if (daemonise) {
		if (nih_main_daemonise () < 0) {
			NihError *err;

			err = nih_error_get ();
			nih_fatal ("%s: %s", _("Unable to become daemon"),
					err->message);
			nih_free (err);

			exit (1);
		}
	}

	if (sigstop)
		raise(SIGSTOP);

	ret = nih_main_loop ();

	/* Destroy any PID file we may have created */
	if (daemonise) {
		nih_main_unlink_pidfile();
	}

	return ret;
}
