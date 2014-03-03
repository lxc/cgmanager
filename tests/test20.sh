#!/bin/bash

echo "Test 20: ListChildren"

# Simple case: current directory
dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.ListChildren string:'memory' string:''
if [ $? -ne 0 ]; then
	echo "Failed to read current directory"
	exit 1
fi

# nonexistent cgroup
dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.Remove string:'memory' string:'ooga2' int32:1 || true
dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.ListChildren string:'memory' string:'ooga2'
if [ $? -eq 0 ]; then
	echo "Wrong result listing nonexistent directory"
	exit 1
fi

# empty cgroup
dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.Create string:'memory' string:'ooga'
dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.ListChildren string:'memory' string:'ooga'
if [ $? -ne 0 ]; then
	echo "Failed to list empty directory"
	exit 1
fi

exit 0
