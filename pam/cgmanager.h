#include <stdbool.h>

bool cgm_dbus_connect(void);
void cgm_dbus_disconnect(void);
bool cgm_create(const char *cg, int *existed);
bool cgm_autoremove(const char *cg);
bool cgm_enter(const char *cg);
bool cgm_chown(const char *cg, uid_t uid, gid_t gid);
char **cgm_list_controllers(void);
char **cgm_list_children(const char *cg);
bool cgm_cg_has_tasks(const char *cg);
void cgm_clear_cgroup(const char *cg);
void cgm_escape(void);
