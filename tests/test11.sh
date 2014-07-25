#!/bin/bash

echo "test 11: unpriv setvalue to first cgroup"
if [ -n "$SUDO_USER" ]; then
	gid=$SUDO_GID
	uid=$SUDO_UID
else
	gid=1000
	uid=1000
fi

sudo -u \#$uid cgm setvalue memory zzz memory.limit_in_bytes 99999
if [ $? -eq 0 ]; then
	exit 1
fi

exit 0
