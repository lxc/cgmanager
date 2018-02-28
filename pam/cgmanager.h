#include <stdbool.h>

#include <nih-dbus/dbus_proxy.h>

bool cgm_dbus_connect(NihDBusProxy **cgroup_manager);
void cgm_dbus_disconnect(NihDBusProxy **cgroup_manager);
bool cgm_create(NihDBusProxy *cgroup_manager, const char *ctrl_list,
		const char *cg, int *existed);
bool cgm_autoremove(NihDBusProxy *cgroup_manager, const char *ctrl_list,
		    const char *cg);
bool cgm_enter(NihDBusProxy *cgroup_manager, const char *ctrl_list,
	       const char *cg);
bool cgm_chown(NihDBusProxy *cgroup_manager, const char *ctrl_list,
	       const char *cg, uid_t uid, gid_t gid);
char **cgm_list_controllers(NihDBusProxy *cgroup_manager);
char **cgm_list_children(NihDBusProxy *cgroup_manager, const char *ctrl_list,
			 const char *cg);
bool cgm_cg_has_tasks(NihDBusProxy *cgroup_manager, const char *ctrl_list,
		      const char *cg);
bool cgm_cg_set_value(NihDBusProxy *cgroup_manager, const char *controller,
		      const char *cg, const char *key, const char *val);
void cgm_clear_cgroup(NihDBusProxy *cgroup_manager, const char *ctrl_list,
		      const char *cg);
bool cgm_escape(NihDBusProxy *cgroup_manager, const char *ctrl_list,
		char **ctrl_list_out, bool *all_ok);
