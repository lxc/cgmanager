#!/bin/bash

# Try to move myself task to xxx/b - should work
echo "Test 8 (movepid self)"
dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.MovePid string:'memory' string:'xxx/b' int32:$$
if [ $? -ne 0 ]; then
	exit 1
fi

exit 0
