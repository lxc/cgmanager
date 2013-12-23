#!/bin/bash

echo "Test 6 (movepid)"
sleep 200 &
pid=$!

# Try to move another task to xxx/b - should work
./movepid -c memory -n xxx/b -p $pid
if [ $? -ne 0 ]; then
	kill -9 $pid
	exit 1
fi
# confirm that it was moved
c=`cat /proc/$pid/cgroup | grep memory | awk -F: '{ print $3 }'`
myc=`cat /proc/$$/cgroup | grep memory | awk -F: '{ print $3 }'`
if [ "$c" != "${myc}/xxx/b" ]; then
	kill -9 $pid
	exit 1
fi

# confirm that getpidcgroup works:
c2=`sudo ./getpidcgroup -c memory -p $pid`
if [ "$c2" != "xxx/b" ]; then
	kill -9 $pid
	exit 1
fi

./movepid -c memory -n xxx -p $pid
if [ $? -ne 0 ]; then
	kill -9 $pid
	exit 1
fi

kill -9 $pid
exit 0
