#!/bin/bash

echo "Test 22: getpidcgroupabs"

cg="test22_cg"

dotest() {
    mount --move /sys/fs/cgroup /mnt || { echo "move mount not allowed;  aborting test"; exit 0; }
    mount -t tmpfs none /sys/fs/cgroup
    mkdir /sys/fs/cgroup/cgmanager
    touch /sys/fs/cgroup/cgmanager/sock
    mount --bind /mnt/cgmanager/sock /sys/fs/cgroup/cgmanager/sock
    cgproxy --debug > cgproxy.out.$$ &
    ppid=$!
    sleep 20 &
    spid=$!
    cgm create memory ab
    dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.Create string:memory string:$cg
    dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.MovePid string:memory string:$cg int32:$spid
    dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.MovePid string:memory string:$cg int32:$$
    p=`dbus-send --print-reply=literal --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.GetPidCgroup string:memory int32:$spid`
    absp=`dbus-send --print-reply=literal --address=unix:path=/sys/fs/cgroup/cgmanager/sock --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.GetPidCgroupAbs string:memory int32:$spid`
    kill -9 $ppid
    kill -9 $spid
    echo "p is .$p."
    echo "absp is .$absp."
    if [ "$p$cg" != "$absp" ]; then
            echo "test 22 failed"
            exit 1
    fi
}

if [ $# -eq 1 ]; then
    dotest
    echo "test 22 passed"
else
    unshare -m $0 unshared
fi
