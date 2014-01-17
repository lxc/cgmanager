#!/bin/bash

echo "Test 7 (non-root movepid)"
# try to move another task to xxx/b without being root - should fail
if [ -n "$SUDO_USER" ]; then
	gid=$SUDO_GID
	uid=$SUDO_UID
else
	gid=1000
	uid=1000
fi

sleep 200 &
pid=$!

sudo -u \#$uid dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.MovePid string:'memory' string:'xxx/b' int32:$pid
if [ $? -eq 0 ]; then
	echo "Failed test 7 - uid $uid could move root-owned sleep"
	exit 1
fi

exit 0
