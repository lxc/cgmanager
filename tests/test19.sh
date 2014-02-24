#!/bin/bash

echo "test 19: escape"
if [ -n "$SUDO_USER" ]; then
	gid=$SUDO_GID
	uid=$SUDO_UID
else
	gid=1000
	uid=1000
fi

cgmescape() {
	dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.MovePidAbs string:memory string:$1 int32:$2
}

orig_cg=`awk -F: '/memory/ { print $3 }' /proc/$$/cgroup`
dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.Create string:memory string:'escapetest'
dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.MovePid string:memory string:'escapetest' int32:$$
new_cg=`awk -F: '/memory/ { print $3 }' /proc/$$/cgroup`
if [ "$orig_cg" = "$new_cg" ]; then
	echo "root was not able to enter the escapetest cgroup"
	echo "orig_cg $orig_cg new-cg $new_cg"
	exit 1
fi

cgmescape / $$
new_cg=`awk -F: '/memory/ { print $3 }' /proc/$$/cgroup`

if [ "$orig_cg" != "$new_cg" ]; then
	echo "root was not able to escape his cgroup"
	echo "orig_cg $orig_cg new-cg $new_cg"
	exit 1
fi

sudo -u \#$uid sleep 200 &
pp=$!
sleep 1
p=`ps -ef | grep sleep | grep $pp | grep -v sudo | tail -1 | awk '{ print $2 }'`

sudo -u \#$uid dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.MovePid string:'memory' string:'/' int32:$p
if [ $? -eq 0 ]; then
	echo "unpriv user was able to move a task to /"
	kill -9 $pp $p
	exit 1
fi

kill -9 $pp $p
exit 0
