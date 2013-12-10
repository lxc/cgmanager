#!/bin/sh

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

stop cgroup-lite || true

# mount memory cgroup and remove our test directories
mount -t cgroup -o memory cgroup /sys/fs/cgroup
rmdir /sys/fs/cgroup/b || true
rmdir /sys/fs/cgroup/xxx/b || true
mkdir /sys/fs/cgroup/xxx
rm -rf /sys/fs/cgroup/zzz
chown -R 1000 /sys/fs/cgroup/xxx
umount /sys/fs/cgroup

dbus-send --print-reply --address=unix:path=/tmp/cgmanager --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.getValue string:'memory' string:'' string:'memory.usage_in_bytes'
if [ $? -ne 0 ]; then
	echo "Failed test 1"
	exit 1
fi
echo "Test 1 (getValue): passed"

dbus-send --print-reply --address=unix:path=/tmp/cgmanager --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.getMyCgroup string:'memory'
if [ $? -ne 0 ]; then
	echo "Failed test 2"
	exit 1
fi
echo "Test 2 (getMyCgroup): passed"

dbus-send --print-reply --address=unix:path=/tmp/cgmanager --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.Create string:'memory' string:"xxx/b"
if [ $? -ne 0 ]; then
	echo "Failed test 3"
	exit 1
fi
echo "Test 3 (Create): passed"

dbus-send --print-reply --address=unix:path=/tmp/cgmanager --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.getValue string:'memory' string:"xxx/b" string:'memory.usage_in_bytes'
if [ $? -ne 0 ]; then
	echo "Failed test 4"
	exit 1
fi
echo "Test 4 (subdir getValue): passed"

#This should fail:
dbus-send --print-reply --address=unix:path=/tmp/cgmanager --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.getValue string:'memory' string:"../xxx/b" string:'memory.usage_in_bytes'
if [ $? -eq 0 ]; then
	echo "Failed test 5: was able to read under \"../xxx\""
	exit 1
fi
echo "Test 5 (../ getValue): passed"

sleep 200 &
pid=$!
# Try to move another task to xxx/b - should work
./movepid -c memory -n xxx/b -p $pid
if [ $? -ne 0 ]; then
	echo "Failed test 6: not able to move another pid"
	exit 1
fi

# confirm that it was moved
c=`cat /proc/$pid/cgroup | grep memory | awk -F: '{ print $3 }'`
if [ "$c" != "/xxx/b" ]; then
	echo "sleep was moved to $c rather than /xxx/b"
	exit 1
fi
echo "Test 6a (movepid): passed"

# confirm that getpidcgroup works:
c2=`sudo ./getpidcgroup -c memory -p $pid`
if [ "$c2" != "xxx/b" ]; then
	echo "Failed test 6b: getpidcgroup returned .$c2. instead of 'xxx/b'"
	exit 1
fi
echo "Test 6b (getpidcgroup): passed"

./movepid -c memory -n xxx -p $pid
if [ $? -ne 0 ]; then
	echo "Failed test 6 cleanup: could not move $pid back to xxx"
	exit 1
fi
echo "Test 6 (movepid): passed"

# try to move another task to xxx/b without being root - should fail
sudo -u \#$uid ./movepid -c memory -n xxx/b -p $pid
if [ $? -eq 0 ]; then
	echo "Failed test 7 - uid $uid could move root-owned sleep"
	exit 1
fi
echo "Test 7 (non-root movepid): passed"

# Try to move myself task to xxx/b - should work
# (useless though since movepid, not its caller, will be moved)
./movepid -c memory -n xxx/b
if [ $? -ne 0 ]; then
	echo "Failed test 8: not able to move myself"
	exit 1
fi
echo "Test 8 (movepid self): passed"

# Try to set a value

# Create a new directory and chown it to calling user;  then try to have
# calling user movepid to the new directory
dbus-send --print-reply --address=unix:path=/tmp/cgmanager --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.Create string:'memory' string:"zzz"
./chowncgroup -c memory -n zzz -u $uid -g $gid
mount -t cgroup -o memory cgroup /sys/fs/cgroup
o1=`stat --format="%u:%g" /sys/fs/cgroup/zzz`
o2=`stat --format="%u:%g" /sys/fs/cgroup/zzz/tasks`
o3=`stat --format="%u:%g" /sys/fs/cgroup/zzz/cgroup.procs`
o4=`stat --format="%u:%g" /sys/fs/cgroup/zzz/memory.limit_in_bytes`
umount /sys/fs/cgroup
if [ "$o1" != "$uid:$gid" ]; then
	echo "Failed test 9: /sys/fs/cgroup/zzz owned by $o1 not $uid:$gid"
	exit 1
fi
if [ "$o2" != "$uid:$gid" ]; then
	echo "Failed test 9: /sys/fs/cgroup/zzz/tasks owned by $o1 not $uid:$gid"
	exit 1
fi
if [ "$o3" != "$uid:$gid" ]; then
	echo "Failed test 9: /sys/fs/cgroup/zzz/cgroup.procs owned by $o1 not $uid:$gid"
	exit 1
fi
if [ "$o4" = "$uid:$gid" ]; then
	echo "Failed test 9: /sys/fs/cgroup/zzz/memory.limit_in_bytes $uid:$gid, should not be"
	exit 1
fi
echo "Test 9 (chownCgroups): passed"
sudo -u \#$uid sleep 200 &
pp=$!
sleep 1
p=`ps -ef | grep sleep | grep $pp | grep -v sudo | tail -1 | awk '{ print $2 }'`
echo "pp is $pp p is $p"
sudo -u \#$uid ./movepid -c memory -n zzz -p $p
if [ $? -ne 0 ]; then
	echo "Failed test 9: uid $uid failed to move his own sleep $p into his own cgroup"
	echo "               (did chown fail?)"
	exit 1
fi

sudo -u \#$uid dbus-send --print-reply --address=unix:path=/tmp/cgmanager --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.setValue string:'memory' string:'zzz' string:'memory.limit_in_bytes' string:'99999'
if [ $? -eq 0 ]; then
	echo 'Failed test 10: non-root could setValue in his first cgroup'
	exit 1
fi

sudo -u \#$uid dbus-send --print-reply --address=unix:path=/tmp/cgmanager --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.Create string:'memory' string:"zzz/b"
if [ $? -ne 0 ]; then
	echo 'Failed test 11: non-root could not create a cgroup zzz/b'
	exit 1
fi

mount -t cgroup -o memory cgroup /sys/fs/cgroup
prev=`cat /sys/fs/cgroup/zzz/b/memory.limit_in_bytes`
umount /sys/fs/cgroup

sudo -u \#$uid dbus-send --print-reply --address=unix:path=/tmp/cgmanager --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.setValue string:'memory' string:'zzz/b' string:'memory.limit_in_bytes' string:'99999'
if [ $? -ne 0 ]; then
	echo 'Failed test 12: non-root could not setValue in his first cgroup'
	exit 1
fi

mount -t cgroup -o memory cgroup /sys/fs/cgroup
after=`cat /sys/fs/cgroup/zzz/b/memory.limit_in_bytes`
umount /sys/fs/cgroup
echo "prev is $prev after is $after"
if [ $prev = $after ]; then
	echo 'Failed test 13: non-root setValue did not take effect'
	exit 1
fi
echo "Test 10 (setValue) passed"

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

echo "All tests passed"
