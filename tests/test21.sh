#!/bin/bash

echo "Test 21: remove_on_empty"

cg="test21_cg"
dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.Remove string:'memory' string:$cg || true
dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.Remove string:'devices' string:$cg || true
dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.Create string:'memory' string:$cg || true
dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.Create string:'devices' string:$cg || true
sleep 200 &
pid=$!
dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.MovePid string:'memory' string:$cg int32:$pid
dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.MovePid string:'devices' string:$cg int32:$pid

dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.RemoveOnEmpty string:'memory' string:$cg

kill $pid

# now $cg should be deleted in memory, but not in devices
# note if logind or upstart has set this for us then this will raise a false positive
dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.GetTasks string:'devices' string:$cg >/dev/null 2>&1
if [ $? -ne 0 ]; then
	echo "Remove-on-empty affected another cgroup"
	exit 1
fi

dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.GetTasks string:'memory' string:$cg >/dev/null 2>&1
if [ $? -eq 0 ]; then
	# Maybe we're on a slow vm.  Kernel needs time to spawn the remove
	# helper.  Give it some time...
	sleep 5
	dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.GetTasks string:'memory' string:$cg >/dev/null 2>&1
	if [ $? -eq 0 ]; then
		echo "Failed to remove-on-empty"
		exit 1
	fi
fi

echo "Test 21 (remove_on_empty) passed"
exit 0
