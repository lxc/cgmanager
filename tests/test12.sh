#!/bin/bash

echo "test 12: valid unpriv cgroup creation"

if [ -n "$SUDO_USER" ]; then
	gid=$SUDO_GID
	uid=$SUDO_UID
else
	gid=1000
	uid=1000
fi

sudo -u \#$uid cgm create memory zzz/b
if [ $? -ne 0 ]; then
	exit 1
fi

exit 0
