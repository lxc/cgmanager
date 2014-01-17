#!/bin/bash
if [ -n "$SUDO_USER" ]; then
	gid=$SUDO_GID
	uid=$SUDO_UID
else
	gid=1000
	uid=1000
fi

echo "test 13: valid unprivileged setvalue"

# Make sure zzz/b is new so it has a full limit to begin with
dbus-send --print-reply=literal --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.Remove string:'memory' string:'zzz/b' int32:1 || true
dbus-send --print-reply=literal --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.Chown string:'memory' string:'zzz' int32:$uid int32:0
sudo -u \#$uid dbus-send --print-reply=literal --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.Create string:'memory' string:'zzz/b'

prev=`dbus-send --print-reply=literal --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.GetValue string:'memory' string:'zzz/b' string:'memory.limit_in_bytes' | awk '{ print $1}'`

new=99999
if [ "$prev" = "102400" ]; then
	new=999999
fi
sudo -u \#$uid dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.SetValue string:'memory' string:'zzz/b' string:'memory.limit_in_bytes' string:"$new" > /dev/null 2>&1
if [ $? -ne 0 ]; then
	echo "test 13: failed to set limit_in_bytes"
	exit 1
fi

after="`dbus-send --print-reply=literal --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.GetValue string:'memory' string:'zzz/b' string:'memory.limit_in_bytes' | awk '{ print $1 }'`"
if [ "$prev" = "$after" ]; then
	echo "test 13: old limit was $prev, new is $after"
	exit 1
fi

exit 0
