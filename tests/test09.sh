#!/bin/bash

# Create a new directory and chown it to calling user;  then try to have
# calling user movepid to the new directory

echo "Test 9 (chownCgroups)"
if [ -n "$SUDO_USER" ]; then
	gid=$SUDO_GID
	uid=$SUDO_UID
else
	gid=1000
	uid=1000
fi

dbus-send --print-reply --address=unix:path=/tmp/cgmanager --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.Create string:'memory' string:"zzz" > /dev/null 2>&1
./chowncgroup -c memory -n zzz -u $uid -g $gid > /dev/null 2>&1
mount -t cgroup -o memory cgroup /sys/fs/cgroup
o1=`stat --format="%u:%g" /sys/fs/cgroup/zzz`
o2=`stat --format="%u:%g" /sys/fs/cgroup/zzz/tasks`
o3=`stat --format="%u:%g" /sys/fs/cgroup/zzz/cgroup.procs`
o4=`stat --format="%u:%g" /sys/fs/cgroup/zzz/memory.limit_in_bytes`
umount /sys/fs/cgroup
if [ "$o1" != "$uid:$gid" ]; then
	exit 1
fi
if [ "$o2" != "$uid:$gid" ]; then
	exit 1
fi
if [ "$o3" != "$uid:$gid" ]; then
	exit 1
fi
if [ "$o4" = "$uid:$gid" ]; then
	exit 1
fi

exit 0
