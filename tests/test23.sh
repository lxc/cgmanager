#!/bin/bash

echo "Test 23: listcontrollers"

for x in `cgm listcontrollers`; do
	if ! grep -q $x /proc/self/cgroup; then
		echo "Bad controller: $x"
		exit 1
	fi
done

echo PASS
