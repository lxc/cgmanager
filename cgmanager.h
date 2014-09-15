#define CGDIR "/sys/fs/cgroup"
#define CGMANAGER_DIR CGDIR "/cgmanager"
#define CGMANAGER_SOCK CGMANAGER_DIR "/sock"
#define CGPROXY_DIR CGDIR "/cgmanager.lower"
#define CGPROXY_SOCK CGPROXY_DIR "/sock"

#define CGMANAGER_DBUS_PATH "unix:path=" CGMANAGER_SOCK
#define CGPROXY_DBUS_PATH "unix:path=" CGPROXY_SOCK

