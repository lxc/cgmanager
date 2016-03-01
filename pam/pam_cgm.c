/* pam-cgm
 *
 * Copyright © 2015 Canonical, Inc
 * Author: Serge Hallyn <serge.hallyn@ubuntu.com>
 *
 * When a user logs in, this pam module will create cgroups which
 * the user may administer, for any controllers listed on the command
 * line or, if none are listed, then all available controllers.
 *
 * The cgroup created will be "user/$user/0" for the first session,
 * "user/$user/1" for the second, etc.
 *
 * See COPYING file for details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>

#define PAM_SM_SESSION
#include <security/_pam_macros.h>
#include <security/pam_modules.h>

#include <linux/unistd.h>

#include <nih-dbus/dbus_connection.h>
#include <nih/alloc.h>
#include <nih/string.h>
#include <nih/error.h>

#include "cgmanager.h"

static void mysyslog(int err, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	openlog("PAM-CGM", LOG_CONS|LOG_PID, LOG_AUTH);
	vsyslog(err, format, args);
	va_end(args);
	closelog();
}

extern char *ctrl_list;

static void get_active_controllers(void)
{
	int i;
	nih_local char **list = cgm_list_controllers();

	if (!list) {
		mysyslog(LOG_NOTICE, "unable to detect controllers");
		ctrl_list = NIH_MUST( nih_strdup(NULL, "all") );
		return;
	}
	for (i = 0; list[i]; i++) {
		NIH_MUST( nih_strcat_sprintf(&ctrl_list, NULL, "%s%s",
			ctrl_list ? "," : "", list[i]) );
	}
}

static bool is_in_list(char *which, char **list) {
	int i;
	size_t wlen = strlen(which);

	for (i = 0; list[i]; i++) {
		char *o = list[i];
		while (o) {
			char *p = index(o, ',');
			size_t len = p ? p - o : strlen(o);

			if (len == wlen && strncmp(o, which, wlen) == 0)
				return true;
			o = p ? p + 1 : NULL;
		}
	}
	return false;
}

static char *validate_and_dup(const char *arg)
{
	nih_local char *d = NIH_MUST( nih_strdup(NULL, arg) );
	nih_local char **valid_list = cgm_list_controllers();
	char *tok;

	if (!valid_list) {
		mysyslog(LOG_ERR, "Failed to get controller list\n");
		return NULL;
	}

	for (tok = strtok(d, ","); tok; tok = strtok(NULL, ",")) {
		if (!is_in_list(tok, valid_list)) {
			mysyslog(LOG_ERR, "Invalid controller: %s\n", tok);
			return NULL;
		}
	}
	return NIH_MUST( nih_strdup(NULL, arg) );
}

static bool get_uid_gid(const char *user, uid_t *uid, gid_t *gid)
{
	struct passwd *pwent;

	pwent = getpwnam(user);
	if (!pwent)
		return false;
	*uid = pwent->pw_uid;
	*gid = pwent->pw_gid;

	return true;
}

#define DIRNAMSZ 200
static int handle_login(const char *user)
{
	int idx = 0, ret;
	int existed = 1;
	size_t ulen = strlen("user/") + strlen(user);
	size_t len = ulen + 50; // Just make sure there's room for "user/$user or an <integer>"
	uid_t uid = 0;
	gid_t gid = 0;
	nih_local char *cg = NIH_MUST( nih_alloc(NULL, len) );

	if (!get_uid_gid(user, &uid, &gid)) {
		mysyslog(LOG_ERR, "failed to get uid and gid for %s\n", user);
		return PAM_SESSION_ERR;
	}

	memset(cg, 0, len);
	strcpy(cg, user);

	ret = snprintf(cg, len, "user/%s", user);
	if (ret < 0 || ret >= len)
		return PAM_SESSION_ERR;

	if (!cgm_create(cg, &existed)) {
		mysyslog(LOG_ERR, "failed to create cgroup %s\n", cg);
		return PAM_SESSION_ERR;
	}

	if (existed == 0) {
		if (!cgm_autoremove(cg)) {
			mysyslog(LOG_ERR, "Warning: failed to set autoremove on %s\n", cg);
		}
	}

	if (!cgm_enter(cg)) {
		mysyslog(LOG_ERR, "failed to enter cgroup %s\n", cg);
		return PAM_SESSION_ERR;
	}

	while (idx >= 0) {
		sprintf(cg, "%d", idx);
		if (!cgm_create(cg, &existed)) {
			mysyslog(LOG_ERR, "failed to create a user cgroup\n");
			return PAM_SESSION_ERR;
		}

		if (existed == 1) {
			idx++;
			continue;
		}

		if (!cgm_chown(cg, uid, gid)) {
			mysyslog(LOG_ERR, "Warning: failed to chown %s\n", cg);
		}

		if (!cgm_autoremove(cg)) {
			mysyslog(LOG_ERR, "Warning: failed to set autoremove on %s\n", cg);
		}

		if (!cgm_enter(cg)) {
			mysyslog(LOG_ERR, "failed to enter user cgroup %s\n", cg);
			return PAM_SESSION_ERR;
		}
		break;
	}

	return PAM_SUCCESS;
}

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
		const char **argv)
{
	const char *PAM_user = NULL;
	int ret;

	if (!cgm_dbus_connect()) {
		mysyslog(LOG_ERR, "Failed to connect to cgmanager\n");
		return PAM_SESSION_ERR;
	}
	if (argc > 1 && strcmp(argv[0], "-c") == 0) {
		ctrl_list = validate_and_dup(argv[1]);
		if (!ctrl_list) {
			cgm_dbus_disconnect();
			mysyslog(LOG_ERR, "PAM-CGM: bad controller arguments\n");
			return PAM_SESSION_ERR;
		}
	}
	if (!ctrl_list)
		get_active_controllers();
	cgm_escape();

	ret = pam_get_user(pamh, &PAM_user, NULL);
	if (ret != PAM_SUCCESS) {
		cgm_dbus_disconnect();
		mysyslog(LOG_ERR, "PAM-CGM: couldn't get user\n");
		return PAM_SESSION_ERR;
	}

	ret = handle_login(PAM_user);
	cgm_dbus_disconnect();
	return ret;
}

static void prune_user_cgs(const char *user)
{
	nih_local char **list = NULL;
	nih_local char *path = NULL;
	int i;

	path = NIH_MUST( nih_sprintf(NULL, "user/%s", user) );
	list = cgm_list_children(path);
	if (!list)
		return;
	for (i = 0; list[i]; i++) {
		nih_local char *cgpath = NIH_MUST( nih_sprintf(NULL, "%s/%s", path, list[i]) );
		if (!cgm_cg_has_tasks(cgpath))
			cgm_clear_cgroup(cgpath);
	}
	if (!cgm_cg_has_tasks(path))
		cgm_clear_cgroup(path);
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
		const char **argv)
{
	const char *PAM_user = NULL;
	int ret = pam_get_user(pamh, &PAM_user, NULL);

	if (ret != PAM_SUCCESS) {
		mysyslog(LOG_ERR, "PAM-CGM: couldn't get user\n");
		return PAM_SESSION_ERR;
	}

	if (cgm_dbus_connect()) {
		if (argc > 1 && strcmp(argv[0], "-c") == 0)
			ctrl_list = validate_and_dup(argv[1]);
		if (!ctrl_list)
			get_active_controllers();
		cgm_escape();
		prune_user_cgs(PAM_user);
		cgm_dbus_disconnect();
	}
	return PAM_SUCCESS;
}
