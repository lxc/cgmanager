#!/bin/bash -x

kmaj=`awk -F. '{ print $1 '} /proc/sys/kernel/osrelease`
kmin=`awk -F. '{ print $2 '} /proc/sys/kernel/osrelease`
if [ $kmaj -eq 3 -a $kmin -eq 16 ]; then
	echo "skipping test 14 (Remove)"
	exit 0
fi

echo "Test 14 (Remove)"
dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.Create string:'memory' string:"xxx/bbb" > /dev/null 2>&1

dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.ListChildren string:'memory' string:"xxx" | grep -q bbb
if [ $? -ne 0 ]; then
	echo "Error durign setup: memory:xxx/b was not created"
	exit 1
fi

# should fail - requires recursive delete
dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.Remove string:'memory' string:"xxx" int32:0 > /dev/null 2>&1
if [ $? -eq 0 ]; then
	echo "non-recursive Remove of non-empty directory wrongly succeeded."
	exit 1
fi

dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.Remove string:'memory' string:"xxx" int32:1 > /dev/null 2>&1
if [ $? -ne 0 ]; then
	echo "recursive remove of directory wrongly failed."
	echo "and here are the contents of memory:''"
	dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.ListChildren string:'memory' string:""
	echo "and here are the contents of memory:xxx"
	dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.ListChildren string:'memory' string:"xxx"
	exit 1
fi

dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.Create string:'memory' string:"xxx/bbb" > /dev/null 2>&1
dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.Remove string:'memory' string:"xxx/bbb" int32:0 > /dev/null 2>&1
if [ $? -ne 0 ]; then
	echo "Failed to remove an empty directory (xxx/b)."
	echo "and here are the contents of memory:''"
	dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.ListChildren string:'memory' string:""
	echo "and here are the contents of memory:xxx"
	dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.ListChildren string:'memory' string:"xxx"
	exit 1
fi
exit 0
