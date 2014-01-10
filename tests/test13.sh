#!/bin/bash
if [ -n "$SUDO_USER" ]; then
	gid=$SUDO_GID
	uid=$SUDO_UID
else
	gid=1000
	uid=1000
fi

echo "test 13: valid unprivileged setvalue"

myc=`cat /proc/$$/cgroup | grep memory | awk -F: '{ print $3 }'`
cantmount=0
mount -t cgroup -o memory cgroup /sys/fs/cgroup || cantmount=1
if [ $cantmount -eq 0 ]; then
	prev=`cat /sys/fs/cgroup/${myc}/zzz/b/memory.limit_in_bytes`
	umount /sys/fs/cgroup
else
	prev=`dbus-send --print-reply=literal --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.getValue string:'memory' string:'zzz/b' string:'memory.usage_in_bytes' | awk '{ print $1}'`
fi

new=99999
if [ "$prev" = "102400" ]; then
	new=999999
fi
sudo -u \#$uid dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.setValue string:'memory' string:'zzz/b' string:'memory.limit_in_bytes' string:"$new" > /dev/null 2>&1
if [ $? -ne 0 ]; then
	echo "test 13: failed to set limit_in_bytes"
	exit 1
fi

if [ $cantmount -eq 0 ]; then
	mount -t cgroup -o memory cgroup /sys/fs/cgroup
	after=`cat /sys/fs/cgroup/${myc}/zzz/b/memory.limit_in_bytes`
	umount /sys/fs/cgroup
else
	after=`dbus-send --print-reply=literal --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.getValue string:'memory' string:'zzz/b' string:'memory.usage_in_bytes' | awk '{ print $1}'`
fi
if [ "$prev" = "$after" ]; then
	echo "test 13: old limit was $prev, new is $after"
	exit 1
fi

exit 0
