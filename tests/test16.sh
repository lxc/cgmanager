#!/bin/bash
if [ -n "$SUDO_USER" ]; then
	gid=$SUDO_GID
	uid=$SUDO_UID
else
	gid=1000
	uid=1000
fi

echo "test 16: INvalid unprivileged setvalue"

# Make sure zzz/b is new so it has a full limit to begin with
cgm remove memory zzz
cgm create memory zzz/b
cgm chown memory zzz/b $uid 0

# Now $uid can create under zzz/b, but should NOT be able to change limits in zzz/b itself

new=99999
sudo -u \#$uid cgm setvalue memory zzz/b memory.limit_in_bytes new
if [ $? -eq 0 ]; then
	echo "test 16: should have failed to set limit_in_bytes!"
	exit 1
fi

exit 0
