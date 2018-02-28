/* pam-cgm
 *
 * Copyright © 2015 Canonical, Inc
 * Author: Serge Hallyn <serge.hallyn@ubuntu.com>
 *
 * Pattern, value setting support and general cleanup:
 * Copyright © 2017 Maciej S. Szmigiero <mail@maciej.szmigiero.name>
 *
 * When a user logs in, this pam module will create cgroups which
 * the user may administer, for any controllers (comma separated) provided
 * to the "--controllers" (or "-c") command line option, or, if this
 * option is missing or set to "all", for all the available controllers.
 *
 * Names of the created cgroups are configurable via a "--pattern" (or "-p")
 * command line option.
 * This pattern-derived name for these cgroups will then have a suffix
 * consisting of a sequential integer appended until the final name - one
 * common for all the controllers - is unique for all of them (this can be
 * disabled using a "--pattern-no-idx-suffix" option).
 * A "--max-idx" (or "-m") option sets how large this sequential number is
 * allowed to grow (numbers are reused once "their" cgroups no longer
 * exist).
 *
 * By default, the created cgroups will be named "user/%u/0" for the first
 * session (where "%u" will be replaced by the user name), "user/%u/1" for
 * the second, etc.
 * All the created cgroups will have "remove on empty" setting enabled for
 * them.
 *
 * The created final cgroups can optionally have values set in them using
 * one or more "--set-value" (or "-s") options.
 * For example, adding a "--set-value io,io.weight,600" parameter to the
 * command line will set in the created final cgroup of the "io" controller
 * a setting named "io.weight" to a value of "600".
 *
 * At the session close (logging out) this module will try to prune the
 * cgroup hierarchy (remove empty cgroups and their children) starting from
 * the final cgroup name and then proceeding towards parent cgroups.
 * A "--prune-depth" command line option sets how deep this prune process goes.
 * The default value of 2 for a final cgroup name of "user/foo/4" will
 * remove a cgroup named "user/foo/4" (if it is empty), then will do the same
 * (check and remove) for a cgroup named "user/foo".
 *
 * The following special placeholders are recognized in a pattern:
 * "%u" - user name,
 * "%U" - user id,
 * "%g" - user primary group name,
 * "%G" - user primary group id,
 * "%p" - current process id (PID),
 * "%P" - current process parent id (PPID),
 * "\%" - a literal "%" character.
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
#include <sys/param.h>
#include <sys/stat.h>
#include <grp.h>
#include <pthread.h>
#include <pwd.h>
#include <limits.h>

#define PAM_SM_SESSION
#include <security/_pam_macros.h>
#include <security/pam_modules.h>

#include <linux/unistd.h>

#include <popt.h>

#include <nih-dbus/dbus_connection.h>
#include <nih/alloc.h>
#include <nih/string.h>
#include <nih/error.h>
#include <nih/list.h>
#include <nih/logging.h>

#include "cgmanager.h"

#define MODULE_NAME "PAM-CGM"

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

#if defined(__GNUC__)
static void mysyslog(int err, const char *format, ...)
	__attribute__ ((format (printf, 2, 3)));
#endif

static void mysyslog(int err, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	openlog(MODULE_NAME, LOG_CONS|LOG_PID, LOG_AUTH);
	vsyslog(err, format, args);
	va_end(args);
	closelog();
}

struct value_set {
	NihList entry;

	char *controller;
	char *setting, *value;
};

static int value_set_destroy(struct value_set *item)
{
	nih_assert(item != NULL);

	if (item->controller != NULL)
		nih_discard(item->controller);

	if (item->setting != NULL)
		nih_discard(item->setting);

	if (item->value != NULL)
		nih_discard(item->value);

	nih_list_destroy(&item->entry);

	return 0;
};

struct handle_data {
	bool session_open;

	NihDBusProxy *cgroup_manager;
	char *ctrl_list;

	char *cpattern;
	int cpattern_no_idx_suffix;
	unsigned int cprune_depth;
	unsigned int cmax_idx;

	NihList values;

	char *cgroup_final_name;
	bool cgroup_created;
};

static void get_active_controllers(struct handle_data *hd)
{
	int i;
	nih_local char **list = cgm_list_controllers(hd->cgroup_manager);

	nih_assert(hd->ctrl_list == NULL);

	if (!list) {
		mysyslog(LOG_NOTICE, "unable to detect controllers");
		hd->ctrl_list = NIH_MUST( nih_strdup(NULL, "all") );
		return;
	}
	for (i = 0; list[i]; i++) {
		NIH_MUST( nih_strcat_sprintf(&hd->ctrl_list, NULL, "%s%s",
					     hd->ctrl_list ? "," : "",
					     list[i]) );
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

static char *validate_and_dup(NihDBusProxy *cgroup_manager, const char *arg)
{
	nih_local char *d = NIH_MUST( nih_strdup(NULL, arg) );
	nih_local char **valid_list = cgm_list_controllers(cgroup_manager);
	char *tok, *savetok;

	if (!valid_list) {
		mysyslog(LOG_ERR, "Failed to get controller list\n");
		return NULL;
	}

	for (tok = strtok_r(d, ",", &savetok); tok;
	     tok = strtok_r(NULL, ",", &savetok)) {
		if (!is_in_list(tok, valid_list)) {
			mysyslog(LOG_ERR, "Invalid controller: %s\n", tok);
			return NULL;
		}
	}
	return NIH_MUST( nih_strdup(NULL, arg) );
}

static bool get_uid_gid(const char *user, uid_t *uid, gid_t *gid)
{
	struct passwd uinfo, *uinfo_out = NULL;
	nih_local char *ubuf = NIH_MUST( nih_alloc(NULL, 2048) );

	nih_assert(user != NULL);
	nih_assert(gid != NULL);
	nih_assert(uid != NULL);

	getpwnam_r(user, &uinfo, ubuf, 2048, &uinfo_out);
	if (uinfo_out == NULL)
		return false;

	*uid = uinfo.pw_uid;
	*gid = uinfo.pw_gid;

	return true;
}

static void prune_cgs(struct handle_data *hd, const char *cpath)
{
	nih_local char *cpathw = NIH_MUST( nih_strdup(NULL, cpath) );
	unsigned int depth;

	for (depth = 0; depth < hd->cprune_depth && cpathw[0] != '\0';
	     depth++) {
		char *c;
		nih_local char **list = cgm_list_children(hd->cgroup_manager,
							  hd->ctrl_list, cpathw);
		unsigned int i;

		for (i = 0; list != NULL && list[i]; i++) {
			nih_local char *cgpath =
				NIH_MUST( nih_sprintf(NULL, "%s/%s",
						      cpathw,
						      list[i]) );

			if (!cgm_cg_has_tasks(hd->cgroup_manager,
					      hd->ctrl_list, cgpath))
				cgm_clear_cgroup(hd->cgroup_manager,
						 hd->ctrl_list, cgpath);
		}

		if (!cgm_cg_has_tasks(hd->cgroup_manager, hd->ctrl_list,
				      cpathw))
			cgm_clear_cgroup(hd->cgroup_manager, hd->ctrl_list,
					 cpathw);

		c = strrchr(cpathw, '/');
		if (c == NULL)
			break;

		while (c >= cpathw && *c == '/') {
			*c = '\0';
			c--;
		}
	}
}

/* based on libcgroup src/api.c::cgroup_change_cgroup_flags() */
static bool get_user_cgroup(const char *pattern, uid_t uid, gid_t gid,
			    char *output, unsigned int outlen)
{
	unsigned int i, j;
	struct passwd uinfo, *uinfo_out = NULL;
	nih_local char *ubuf = NULL;
	struct group grinfo, *grinfo_out = NULL;
	nih_local char *grbuf = NULL;

	nih_assert(pattern != NULL);
	nih_assert(output != NULL);
	nih_assert(outlen >= 2);

	for (j = i = 0;
	     i < strlen(pattern) &&
		     (j < outlen - 2);
	     ++i, ++j) {
		unsigned int available;
		int written;

		if (pattern[i] != '%') {
			if (pattern[i] == '\\')
				++i;

			output[j] = pattern[i];

			continue;
		}

		/* How many bytes can we write */
		available = outlen - j - 2;
		/* Substitution */
		switch (pattern[++i]) {
		case 'U':
			written = snprintf(output + j,
					   available,
					   "%u",
					   (unsigned int)uid);
			break;
		case 'u':
			if (uinfo_out == NULL) {
				ubuf = NIH_MUST( nih_alloc(NULL, 2048) );
				getpwuid_r(uid, &uinfo, ubuf, 2048, &uinfo_out);
			}
			if (uinfo_out != NULL)
				written = snprintf(output + j,
						   available, "%s",
						   uinfo.pw_name);
			else
				written = snprintf(output + j,
						   available,
						   "%u",
						   (unsigned int)uid);
			break;
		case 'G':
			written = snprintf(output + j,
					   available, "%u",
					   (unsigned int)gid);
			break;
		case 'g':
			if (grinfo_out == NULL) {
				grbuf = NIH_MUST( nih_alloc(NULL, 2048) );
				getgrgid_r(gid, &grinfo, grbuf, 2048, &grinfo_out);
			}
			if (grinfo_out != NULL)
				written = snprintf(output + j,
						   available, "%s",
						   grinfo.gr_name);
			else
				written = snprintf(output + j,
						   available, "%u",
						   (unsigned int)gid);
			break;
		case 'P':
			written = snprintf(output + j,
					   available, "%d",
					   (int)getppid());
			break;
		case 'p':
			written = snprintf(output + j,
					   available, "%d",
					   (int)getpid());
			break;
		default:
			written = 0;
		}

		if (written > 0 && written > available)
			written = available;
		/*
		 * written < 1 only when either error occurred
		 * during snprintf or if no substitution was
		 * made at all. In both cases, we want to just
		 * copy input string.
		 */
		if(written < 1) {
			output[j] = '%';
			if(available > 1)
				output[++j] =
					pattern[i];
		} else {
			/*
			 * In next iteration, we will write
			 * just after the substitution, but j
			 * will get incremented in the
			 * meantime.
			 */
			j += written - 1;
		}
	}

	output[j] = '\0';

	return true;
}

static void set_values(struct handle_data *hd, const char *cgroup)
{
	char *clist[2] = { hd->ctrl_list, NULL };

	NIH_LIST_FOREACH(&hd->values, entry) {
		struct value_set *value = (struct value_set *)entry;

		nih_assert(value->controller != NULL);
		if (!is_in_list(value->controller, clist))
			continue;

		nih_assert(value->setting != NULL);
		nih_assert(value->value != NULL);
		if (!cgm_cg_set_value(hd->cgroup_manager, value->controller,
				      cgroup, value->setting, value->value)) {
			mysyslog(LOG_WARNING,
				 "failed to set %s = %s in cgroup %s (ctr %s)\n",
				 value->setting, value->value, cgroup,
				 value->controller);
		}
	}
}

static int handle_login(struct handle_data *hd, const char *user)
{
	uid_t uid = 0;
	gid_t gid = 0;
	unsigned int idx;
	nih_local char *cpath = NULL;
	char *cpath_end, *cpath_last_part;
	unsigned int cpath_space;

	if (!get_uid_gid(user, &uid, &gid)) {
		mysyslog(LOG_ERR, "failed to get uid and gid for %s\n", user);
		return PAM_SESSION_ERR;
	}

	cpath = NIH_MUST( nih_alloc(NULL, MAXPATHLEN) );
	if (!get_user_cgroup(hd->cpattern, uid, gid, cpath, MAXPATHLEN)) {
		mysyslog(LOG_ERR,
			 "failed to get cgroup name for %s\n", user);
		return PAM_SESSION_ERR;
	}

	do {
		char *end, *begin_cur;
		nih_local char *cpath_part = NULL;
		bool first;

		end = strrchr(cpath, '/');
		/* no '/'s in path - no intermediate cgroups */
		if (end == NULL) {
			cpath_last_part = cpath;
			break;
		}

		cpath_part = NIH_MUST( nih_alloc(NULL, end - cpath + 1) );

		begin_cur = cpath;

		if (*begin_cur == '/')
			/* position at the last '/' char of prefix of '/'s */
			while (begin_cur < end && *(begin_cur + 1) == '/')
				begin_cur++;

		if (begin_cur >= end) {
			/* the whole path contains just '/'s */
			cpath_last_part = cpath;
			break;
		} else
			cpath_last_part = end + 1;

		first = true;
		while (1) {
			char *begin_cur_search, *end_cur;
			int existed;

			if (first) {
				/* ignore '/' at the very first position in the cgroup path */
				begin_cur_search = begin_cur + 1;
				first = false;
			} else
				begin_cur_search = begin_cur;

			end_cur = strchr(begin_cur_search, '/');
			if (end_cur == NULL || end_cur > end)
				break;

			/* include all the suffix '/'s in the path */
			while (end_cur < end && *(end_cur + 1) == '/')
				end_cur++;

			memcpy(cpath_part, begin_cur, end_cur - begin_cur);
			cpath_part[end_cur - begin_cur] = '\0';
			if (!cgm_create(hd->cgroup_manager, hd->ctrl_list,
					cpath_part, &existed)) {
				mysyslog(LOG_ERR,
					 "failed to create intermediate user cgroup %s\n",
					 cpath_part);
				return PAM_SESSION_ERR;
			}

			if (!cgm_enter(hd->cgroup_manager, hd->ctrl_list,
				       cpath_part)) {
				mysyslog(LOG_ERR, "failed to enter intermediate user cgroup %s\n",
					 cpath_part);

				if (existed != 1)
					cgm_autoremove(hd->cgroup_manager,
						       hd->ctrl_list,
						       cpath_part);

				return PAM_SESSION_ERR;
			}

			if (existed != 1 && !cgm_autoremove(hd->cgroup_manager,
							    hd->ctrl_list,
							    ""))
				mysyslog(LOG_ERR,
					 "Warning: failed to set autoremove on %s\n",
					 cpath_part);

			begin_cur = end_cur + 1;
		}
	} while (0);

	nih_assert(strlen(cpath) < MAXPATHLEN);
	cpath_end = cpath + strlen(cpath);
	cpath_space = MAXPATHLEN - strlen(cpath);

	nih_assert(hd->cmax_idx >= 1);
	for (idx = 0; idx < hd->cmax_idx; idx++) {
		int existed;

		if (!hd->cpattern_no_idx_suffix) {
			snprintf(cpath_end,
				 cpath_space, "%u", idx);
			cpath[MAXPATHLEN - 1] = '\0';
		}

		if (!cgm_create(hd->cgroup_manager, hd->ctrl_list,
				cpath_last_part, &existed)) {
			mysyslog(LOG_ERR,
				 "failed to create a user cgroup %s\n",
				 cpath_last_part);
			goto ret_fail;
		}

		if (!hd->cpattern_no_idx_suffix && existed == 1)
			continue;

		if (existed != 1) {
			if (!cgm_chown(hd->cgroup_manager, hd->ctrl_list,
				       cpath_last_part, uid, gid))
				mysyslog(LOG_ERR,
					 "Warning: failed to chown %s\n",
					 cpath_last_part);

			set_values(hd, cpath_last_part);
		}

		if (!cgm_enter(hd->cgroup_manager, hd->ctrl_list,
			       cpath_last_part)) {
			mysyslog(LOG_ERR, "failed to enter user cgroup %s\n",
				 cpath_last_part);

			if (existed != 1)
				cgm_autoremove(hd->cgroup_manager,
					       hd->ctrl_list,
					       cpath_last_part);

			goto ret_fail;
		}

		if (existed != 1 && !cgm_autoremove(hd->cgroup_manager,
						    hd->ctrl_list,
						    ""))
			mysyslog(LOG_ERR,
				 "Warning: failed to set autoremove on %s\n",
				 cpath_last_part);

		nih_assert(hd->cgroup_final_name == NULL);
		hd->cgroup_final_name = NIH_MUST( nih_strdup(NULL, cpath) );
		hd->cgroup_created = existed != 1;

		return PAM_SUCCESS;
	}

	mysyslog(LOG_ERR, "max idx reached, cgroup not created\n");

ret_fail:
	if (cpath != NULL)
		prune_cgs(hd, cpath);

	return PAM_SESSION_ERR;
}

static bool process_options_build_ctrls(struct handle_data *hd, int argc,
					const char **argv)
{
	char *controllers = NULL;
	char *cpattern = "user/%u/";
	int prune_depth = 2; /* prune user name and session idx cgroups by default */;
	int max_idx = 100;
	poptContext poptCtx;
	int poptRet;
	bool ret = false;

	const struct poptOption options[] = {
		{ "controllers", 'c', POPT_ARG_STRING, &controllers, 0, NULL,
		  NULL },

		{ "pattern", 'p', POPT_ARG_STRING, &cpattern, 0, NULL, NULL },
		{ "pattern-no-idx-suffix", '\0', POPT_ARG_NONE,
		  &hd->cpattern_no_idx_suffix, 0, NULL, NULL },

		{ "prune-depth", '\0', POPT_ARG_INT, &prune_depth, 0, NULL,
		  NULL },
		{ "max-idx", 'm', POPT_ARG_INT, &max_idx, 0, NULL, NULL },

		{ "set-value", 's', POPT_ARG_STRING, NULL, 's', NULL, NULL },

		POPT_TABLEEND
	};

	poptCtx = poptGetContext(MODULE_NAME, argc, argv, options,
				 POPT_CONTEXT_KEEP_FIRST);
	while ((poptRet = poptGetNextOpt(poptCtx)) > 0) {
		if (poptRet == 's') {
			char *arg = poptGetOptArg(poptCtx);
			char *setting, *val;
			struct value_set *entry;

			if (arg == NULL) {
				mysyslog(LOG_ERR,
					 "cannot get set-value arg, ignoring\n");
				continue;
			}

			setting = strchr(arg, ',');
			if (setting == NULL) {
				mysyslog(LOG_ERR,
					 "cannot get controller from set-value arg\n");
				free(arg);
				goto ret_free;
			}
			*setting = '\0';
			setting++;

			val = strchr(setting, ',');
			if (val == NULL) {
				mysyslog(LOG_ERR,
					 "cannot get value from set-value arg\n");
				free(arg);
				goto ret_free;
			}
			*val = '\0';
			val++;

			entry = NIH_MUST( nih_alloc(NULL, sizeof(*entry)) );
			nih_list_init(&entry->entry);
			entry->controller = NIH_MUST( nih_strdup(NULL, arg) );
			entry->setting = NIH_MUST( nih_strdup(NULL, setting) );
			entry->value = NIH_MUST( nih_strdup(NULL, val) );

			nih_list_add(&hd->values, &entry->entry);
			nih_alloc_set_destructor(entry, value_set_destroy);

			free(arg);
		} else
			mysyslog(LOG_WARNING, "unknown popt return value %d\n",
				 poptRet);
	}
	if (poptRet != -1) {
		mysyslog(LOG_ERR, "%s: %s\n",
			 poptBadOption(poptCtx, POPT_BADOPTION_NOALIAS),
			 poptStrerror(poptRet));
		goto ret_free;
	}

	if (controllers == NULL || strcmp(controllers, "all") == 0)
		get_active_controllers(hd);
	else {
		hd->ctrl_list = validate_and_dup(hd->cgroup_manager,
						 controllers);
		if (hd->ctrl_list == NULL) {
			mysyslog(LOG_ERR, "bad controller arguments\n");
			goto ret_free;
		}
	}

	hd->cpattern = NIH_MUST( nih_strdup(NULL, cpattern) );

	if (prune_depth < 0) {
		mysyslog(LOG_ERR, "prune depth can't be negative\n");
		goto ret_free;
	}
	hd->cprune_depth = prune_depth;

	if (max_idx < 1) {
		mysyslog(LOG_ERR, "max idx must be at least 1\n");
		goto ret_free;
	}
	hd->cmax_idx = max_idx;

	ret = true;

ret_free:
	poptFreeContext(poptCtx);
	return ret;
}

static void hd_cleanup(pam_handle_t *pamh, void *data, int error_status)
{
	struct handle_data *hd = data;

	if (hd->ctrl_list != NULL)
		nih_discard(hd->ctrl_list);

	if (hd->cpattern != NULL)
		nih_discard(hd->cpattern);

	if (hd->cgroup_final_name != NULL)
		nih_discard(hd->cgroup_final_name);

	if (hd->cgroup_manager != NULL)
		mysyslog(LOG_ERR,
			 "cleaning up a handle that is still connected - bad\n");

	while (!NIH_LIST_EMPTY(&hd->values))
		nih_free(hd->values.next);

	nih_discard(hd);
}

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
			const char **argv)
{
	const void *hd_ptr;
	struct handle_data *hd;
	const char *PAM_user = NULL;
	int ret;

	if (pam_get_data(pamh, MODULE_NAME, &hd_ptr) != PAM_SUCCESS) {
		hd = NIH_MUST( nih_alloc(NULL, sizeof(*hd)) );
		memset(hd, 0, sizeof(*hd));
		nih_list_init(&hd->values);

		ret = pam_set_data(pamh, MODULE_NAME, hd, hd_cleanup);
		if (ret != PAM_SUCCESS) {
			nih_discard(hd);
			mysyslog(LOG_ERR, "cannot set handle data (%d)\n", ret);
			return ret;
		}
	} else
		hd = (struct handle_data *)hd_ptr;

	nih_assert(hd != NULL);

	if (hd->session_open) {
		mysyslog(LOG_ERR,
			 "this PAM handle already has an open session\n");
		return PAM_SYSTEM_ERR;
	}

	if (!cgm_dbus_connect(&hd->cgroup_manager)) {
		mysyslog(LOG_ERR, "Failed to connect to cgmanager\n");
		ret = PAM_SESSION_ERR;
		goto ret_exit;
	}

	if (pthread_mutex_lock(&mutex) != 0) {
		mysyslog(LOG_ERR, "unable to lock mutex\n");
		ret = PAM_SESSION_ERR;
		goto ret_disc;
	}

	if (!process_options_build_ctrls(hd, argc, argv)) {
		ret = PAM_SESSION_ERR;
		goto ret_unlock;
	}

	do {
		char *ctrls_new;
		if (!cgm_escape(hd->cgroup_manager, hd->ctrl_list, &ctrls_new,
				NULL)) {
			mysyslog(LOG_ERR, "cannot escape into root cgroups\n");
			ret = PAM_SESSION_ERR;
			goto ret_unlock;
		}

		nih_discard(hd->ctrl_list);
		hd->ctrl_list = ctrls_new;
	} while (0);

	ret = pam_get_user(pamh, &PAM_user, NULL);
	if (ret != PAM_SUCCESS) {
		mysyslog(LOG_ERR, "couldn't get user\n");
		goto ret_unlock;
	}

	ret = handle_login(hd, PAM_user);

ret_unlock:
	pthread_mutex_unlock(&mutex);

ret_disc:
	cgm_dbus_disconnect(&hd->cgroup_manager);

ret_exit:
	if (ret == PAM_SUCCESS)
		hd->session_open = true;
	else
		pam_set_data(pamh, MODULE_NAME, NULL, NULL);

	return ret;
}

void do_close_session(struct handle_data *hd)
{
	char *ctrls_new;

	if (pthread_mutex_lock(&mutex) != 0) {
		mysyslog(LOG_ERR, "unable to lock mutex\n");
		return;
	}

	if (!cgm_escape(hd->cgroup_manager, hd->ctrl_list, &ctrls_new,
			NULL)) {
		mysyslog(LOG_ERR, "cannot escape into root cgroups on session close\n");
		goto ret_unlock;
	}

	nih_discard(hd->ctrl_list);
	hd->ctrl_list = ctrls_new;

	if (hd->cgroup_created) {
		nih_assert(hd->cgroup_final_name != NULL);
		if (!cgm_cg_has_tasks(hd->cgroup_manager, hd->ctrl_list,
				      hd->cgroup_final_name))
			cgm_clear_cgroup(hd->cgroup_manager,
					 hd->ctrl_list, hd->cgroup_final_name);
	}

	if (hd->cgroup_final_name != NULL)
		prune_cgs(hd, hd->cgroup_final_name);

ret_unlock:
	pthread_mutex_unlock(&mutex);
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
			 const char **argv)
{
	const void *hd_ptr;
	struct handle_data *hd;
	int ret;

	ret = pam_get_data(pamh, MODULE_NAME, &hd_ptr);
	if (ret != PAM_SUCCESS) {
		mysyslog(LOG_ERR, "cannot get handle data (%d)\n", ret);
		return ret;
	} else
		hd = (struct handle_data *)hd_ptr;

	if (!hd->session_open) {
		mysyslog(LOG_ERR,
			 "this PAM handle session isn't open (concurrency problem?)\n");
		return PAM_SYSTEM_ERR;
	}

	if (cgm_dbus_connect(&hd->cgroup_manager)) {
		do_close_session(hd);
		cgm_dbus_disconnect(&hd->cgroup_manager);
	}

	hd->session_open = false;
	pam_set_data(pamh, MODULE_NAME, NULL, NULL);

	return PAM_SUCCESS;
}
