#!/bin/bash

echo "Test 6 (movepid)"
sleep 200 &
pid=$!

echo 1
# Try to move another task to xxx/b - should work
dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.MovePid string:'memory' string:'xxx/b' int32:$pid
if [ $? -ne 0 ]; then
	kill -9 $pid
	exit 1
fi
echo 2
# confirm that it was moved
c="`cat /proc/$pid/cgroup | grep memory | awk -F: '{ print $3 }'`"
myc="`cat /proc/$$/cgroup | grep memory | awk -F: '{ print $3 }'`"
ok=0
if [ "$c" = "${myc}/xxx/b" ]; then
	ok=1;
fi
if [ "$myc" = "/" -a "$c" = "/xxx/b" ]; then
	ok=1;
fi
if [ $ok -eq 0 ]; then
	echo "c is .$c. myc is .$myc."
	kill -9 $pid
	exit 1
fi

c2=`dbus-send --print-reply=literal --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.GetPidCgroup string:'memory' int32:$pid | awk '{ print $1}'`
if [ "$c2" != "xxx/b" ]; then
	echo "got $c2 instead of xxx/b"
	kill -9 $pid
	exit 1
fi

echo 4
dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.MovePid string:'memory' string:'xxx' int32:$pid
if [ $? -ne 0 ]; then
	kill -9 $pid
	exit 1
fi
echo 5

kill -9 $pid
exit 0
