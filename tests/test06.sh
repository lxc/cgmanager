#!/bin/bash

echo "Test 6 (movepid)"
sleep 200 &
pid=$!

echo 1
# Try to move another task to xxx/b - should work
movepid -c memory -n xxx/b -p $pid
if [ $? -ne 0 ]; then
	kill -9 $pid
	exit 1
fi
echo 2
# confirm that it was moved
c=`cat /proc/$pid/cgroup | grep memory | awk -F: '{ print $3 }'`
myc=`cat /proc/$$/cgroup | grep memory | awk -F: '{ print $3 }'`
ok=0
if [ "$c" == "${myc}/xxx/b" ]; then
	ok=1;
fi
if [ "$myc" == "/" -a "$c" == "/xxx/b" ]; then
	ok=1;
fi
if [ $ok -eq 0 ]; then
	echo "c is .$c. myc is .$myc."
	kill -9 $pid
	exit 1
fi

echo 3
# confirm that getpidcgroup works:
c2=`sudo getpidcgroup -c memory -p $pid`
if [ "$c2" != "xxx/b" ]; then
	kill -9 $pid
	exit 1
fi

echo 4
movepid -c memory -n xxx -p $pid
if [ $? -ne 0 ]; then
	kill -9 $pid
	exit 1
fi
echo 5

kill -9 $pid
exit 0
