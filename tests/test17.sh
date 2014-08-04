#!/bin/bash
if [ -n "$SUDO_USER" ]; then
	gid=$SUDO_GID
	uid=$SUDO_UID
else
	gid=1000
	uid=1000
fi

mnt=`mktemp -d`

cleanup() {
	umount $mnt || true
	rmdir $mnt
}

trap cleanup EXIT

echo "test 17: chown"

# We can't readily verify if we can't mount cgroups
cantmount=0
mount -t cgroup -o memory cgroup $mnt || cantmount=1

# Create /testchown cgroup owned by root
cgm remove memory testchown
cgm create memory testchown

cgm chmodfile memory testchown tasks 0775
if [ $cantmount -eq 0 ]; then
	myc=`cat /proc/$$/cgroup | grep memory | awk -F: '{ print $3 }'`
	path="${mnt}/${myc}/testchown/tasks"
	newmode=`stat -c "%a" $path`
	if [ "$newmode" != "775" ]; then
		echo "test 17: root was not able to chmod tasks file"
		echo "test 17: mode was $newmode not 775"
		exit 1
	fi
else
	echo "Cannot verify results"
fi

# Create /testchown cgroup owned by root
cgm remove memory testchown
cgm create memory testchown
sudo -u \#$uid cgm chmodfile memory testchown tasks 0775
if [ $? -eq 0 ]; then
	echo "test 17: should have failed to chmod tasks file"
	exit 1
fi

# chown the cgroup so that unprivileged user should be able to chmod it.
cgm chown memory testchown $uid 0

sudo -u \#$uid cgm chmodfile  memory testchown tasks 0775
if [ $? -ne 0 ]; then
	echo "test 17: should have succeeded chmoding tasks file as non-root"
	exit 1
fi
if [ $cantmount -eq 0 ]; then
	myc=`cat /proc/$$/cgroup | grep memory | awk -F: '{ print $3 }'`
	path="${mnt}/${myc}/testchown/tasks"
	newmode=`stat -c "%a" $path`
	if [ "$newmode" != "775" ]; then
		echo "test 17: user was not able to chmod his own tasks file"
		exit 1
	fi
fi

echo "test 17 (chmod) passed"

exit 0
