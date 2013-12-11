#!/bin/bash

dbus-send --print-reply --address=unix:path=/tmp/cgmanager --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.getValue string:'memory' string:"xxx/b" string:'memory.usage_in_bytes' > /dev/null 2>&1
if [ $? -ne 0 ]; then
	exit 1
fi
exit 0
