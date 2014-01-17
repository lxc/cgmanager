#!/bin/bash

echo "test 11: unpriv setvalue to first cgroup"
if [ -n "$SUDO_USER" ]; then
	gid=$SUDO_GID
	uid=$SUDO_UID
else
	gid=1000
	uid=1000
fi

sudo -u \#$uid dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.SetValue string:'memory' string:'zzz' string:'memory.limit_in_bytes' string:'99999' > /dev/null 2>&1
if [ $? -eq 0 ]; then
	exit 1
fi

exit 0
