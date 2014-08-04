#!/bin/bash

# for expediency this test script assumes you're on recent ubuntu

if [ "$(id -u)" != "0" ]; then
	echo "Run as root"
	exit 0
fi

if [ -n "$SUDO_USER" ]; then
	gid=$SUDO_GID
	uid=$SUDO_UID
else
	gid=1000
	uid=1000
fi
echo "Note: real uid is $uid gid is $gid user is $SUDO_USER"

cgm ping || { echo "cgmanager is not running"; exit 1; }

# mount memory cgroup and remove our test directories
mount -t cgroup -o memory cgroup /sys/fs/cgroup
rmdir /sys/fs/cgroup/b || true
rmdir /sys/fs/cgroup/xxx/b || true
rmdir /sys/fs/cgroup/zzz/b || true
rmdir /sys/fs/cgroup/zzz || true
mkdir /sys/fs/cgroup/xxx
chown -R $uid /sys/fs/cgroup/xxx
umount /sys/fs/cgroup

bname=`dirname "${BASH_SOURCE[0]}"`
cd $bname
DIR=`pwd`
count=1
for t in $DIR/test*.sh; do
	f="./$(basename $t)"
	$f || { echo "Test $count failed."; exit 1; }
	count=$((count+1))
done

# Figure out whether the caller has subuids
if ! grep -q "^$USER:" /etc/subuid; then
	echo "$USER has no subuids;  skipping user ns tests"
	exit 0
fi
if ! which lxc-usernsexec > /dev/null 2>&1; then
	echo "lxc-usernsexec is not installed;  skipping user ns tests"
	exit 0
fi

echo "Running userns tests"
count=1
for t in $DIR/usernstest*.sh; do
	f="./$(basename $t)"
	$f || { echo "Userns test $count failed."; exit 1; }
	count=$((count+1))
done


echo "All tests passed"
