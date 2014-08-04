#!/bin/bash

echo "Test 22: getpidcgroupabs"

cg="test22_cg"

dotest() {
    mount --move /sys/fs/cgroup /mnt || { echo "move mount not allowed;  aborting test"; exit 0; }
    mount -t tmpfs none /sys/fs/cgroup
    mkdir /sys/fs/cgroup/cgmanager
    touch /sys/fs/cgroup/cgmanager/sock
    mount --bind /mnt/cgmanager/sock /sys/fs/cgroup/cgmanager/sock
    cgproxy &
    ppid=$!
    sleep 20 &
    spid=$!
    cgm create memory ab
    cgm create memory $cg
    cgm movepid memory $cg $spid
    cgm movepid memory $cg $$
    p=`cgm getpidcgroup memory $spid`
    absp=`cgm getpidcgroupabs memory $spid`
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
