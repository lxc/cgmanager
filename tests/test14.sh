#!/bin/bash

echo "Test 14 (Remove)"
dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.Create string:'memory' string:"xxx/b" > /dev/null 2>&1

# should fail - requires recursive delete
dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.Remove string:'memory' string:"xxx" int32:0 > /dev/null 2>&1
if [ $? -eq 0 ]; then
	exit 1
fi

dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.Remove string:'memory' string:"xxx" int32:1 > /dev/null 2>&1
if [ $? -ne 0 ]; then
	exit 1
fi

dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.Create string:'memory' string:"xxx/b" > /dev/null 2>&1
dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.Remove string:'memory' string:"xxx/b" int32:0 > /dev/null 2>&1
if [ $? -ne 0 ]; then
	exit 1
fi
exit 0
