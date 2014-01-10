#!/bin/bash

echo "Test 2 (getMyCgroup)"
dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.getPidCgroup string:'memory' int32:$$ > /dev/null 2>&1
if [ $? -ne 0 ]; then
	exit 1
fi
exit 0
