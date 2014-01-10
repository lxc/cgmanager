#!/bin/bash

echo "Test 3 (Create)"
dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.Create string:'memory' string:"xxx/b" > /dev/null 2>&1
if [ $? -ne 0 ]; then
	exit 1
fi
exit 0
