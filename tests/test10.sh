#!/bin/bash

echo "test 10: unpriv movepid to chowned directory"
if [ -n "$SUDO_USER" ]; then
	gid=$SUDO_GID
	uid=$SUDO_UID
else
	gid=1000
	uid=1000
fi

sudo -u \#$uid sleep 200 &
pp=$!
sleep 1
p=`ps -ef | grep sleep | grep $pp | grep -v sudo | tail -1 | awk '{ print $2 }'`
sudo -u \#$uid cgm movepid memory zzz $p
if [ $? -ne 0 ]; then
	kill -9 $pp $p
	exit 1
fi

kill -9 $pp $p
exit 0
