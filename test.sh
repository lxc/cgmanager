#!/bin/sh

# for expediency this test script assumes you're on recent ubuntu

if [ "$(id -u)" != "0" ]; then
	echo "Run as root"
	exit 0
fi

stop cgroup-lite || true

# mount memory cgroup and remove our test directories
mount -t cgroup -o memory cgroup /sys/fs/cgroup
rmdir /sys/fs/cgroup/b || true
rmdir /sys/fs/cgroup/xxx/b || true
mkdir /sys/fs/cgroup/xxx
chown -R 1000 /sys/fs/cgroup/xxx
umount /sys/fs/cgroup

dbus-send --print-reply --address=unix:path=/tmp/cgmanager --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.getValue string:'memory' string:'' string:'memory.usage_in_bytes'
if [ $? -ne 0 ]; then
	echo "Failed test 1"
	exit 1
fi

dbus-send --print-reply --address=unix:path=/tmp/cgmanager --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.getMyCgroup string:'memory'
if [ $? -ne 0 ]; then
	echo "Failed test 2"
	exit 1
fi

dbus-send --print-reply --address=unix:path=/tmp/cgmanager --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.Create string:'memory' string:"xxx/b"
if [ $? -ne 0 ]; then
	echo "Failed test 3"
	exit 1
fi

dbus-send --print-reply --address=unix:path=/tmp/cgmanager --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.getValue string:'memory' string:"xxx/b" string:'memory.usage_in_bytes'
if [ $? -ne 0 ]; then
	echo "Failed test 4"
	exit 1
fi

#This should fail:
dbus-send --print-reply --address=unix:path=/tmp/cgmanager --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.getValue string:'memory' string:"../xxx/b" string:'memory.usage_in_bytes'
if [ $? -eq 0 ]; then
	echo "Failed test 5: was able to read under \"../xxx\""
	exit 1
fi

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

# confirm that getpidcgroup works:
c2=`sudo ./getpidcgroup -c memory -p $pid`
if [ "$c2" != "xxx/b" ]; then
	echo "Failed test 6b: getpidcgroup returned .$c2. instead of 'xxx/b'"
	exit 1
fi

./movepid -c memory -n xxx -p $pid
if [ $? -ne 0 ]; then
	echo "Failed test 6 cleanup: could not move $pid back to xxx"
	exit 1
fi

# try to move another task to xxx/b without being root - should fail
sudo -u \#1000 ./movepid -c memory -n xxx/b -p $pid
if [ $? -eq 0 ]; then
	echo "Failed test 7 - uid 1000 could move root-owned sleep"
	exit 1
fi

# Try to move myself task to xxx/b - should work
# (useless though since movepid, not its caller, will be moved)
./movepid -c memory -n xxx/b
if [ $? -ne 0 ]; then
	echo "Failed test 8: not able to move myself"
	exit 1
fi

echo "All tests passed"
