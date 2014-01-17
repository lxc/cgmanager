#!/bin/bash

ret=0
echo "Test 14 (nrtasks)"

dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.Create string:'memory' string:"xxx/c" > /dev/null 2>&1

sleep 200 &
pid=$!

dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.MovePid string:'memory' string:"xxx/c" int32:$pid > /dev/null 2>&1

result=`dbus-send --print-reply=literal --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.GetTasks string:'memory' string:"xxx/c" | awk '/int32/ { print $2 }'`

if [ "$result" != "$pid" ]; then
	echo "result is $result not $pid"
	ret=1
fi

kill -9 $pid 2>&1 > /dev/null

dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.Remove string:'memory' string:"xxx/c" int32:0 > /dev/null 2>&1

exit $ret
