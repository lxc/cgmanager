#!/bin/bash

echo "Test 1: getValue"

dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.getValue string:'memory' string:'' string:'memory.usage_in_bytes' > /dev/null 2>&1
if [ $? -ne 0 ]; then
	exit 1
fi
exit 0
