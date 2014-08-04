#!/bin/bash -x
if [ -n "$SUDO_USER" ]; then
	gid=$SUDO_GID
	uid=$SUDO_UID
else
	gid=1000
	uid=1000
fi

echo "test 13: valid unprivileged setvalue"

# Make sure zzz/b is new so it has a full limit to begin with
cgm remove memory zzz/b 1
cgm chown memory zzz $uid 0
sudo -u \#$uid cgm create memory zzz/b

prev=`cgm getvalue memory zzz/b memory.limit_in_bytes`

new=99999
if [ "$prev" = "102400" ]; then
	new=999999
fi
sudo -u \#$uid cgm setvalue memory zzz/b memory.limit_in_bytes $new
if [ $? -ne 0 ]; then
	echo "test 13: failed to set limit_in_bytes"
	exit 1
fi

after=`cgm getvalue memory zzz/b memory.limit_in_bytes`
if [ "$prev" = "$after" ]; then
	echo "test 13: old limit was $prev, new is $after"
	exit 1
fi

exit 0
