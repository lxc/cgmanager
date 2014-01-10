#!/bin/bash

echo "test 12: valid unpriv cgroup creation"

if [ -n "$SUDO_USER" ]; then
	gid=$SUDO_GID
	uid=$SUDO_UID
else
	gid=1000
	uid=1000
fi

sudo -u \#$uid dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.Create string:'memory' string:"zzz/b" > /dev/null 2>&1
if [ $? -ne 0 ]; then
	exit 1
fi

exit 0
