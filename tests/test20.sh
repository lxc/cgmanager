#!/bin/bash

echo "Test 20: ListChildren"

# Simple case: current directory
cgm listchildren memory ''
if [ $? -ne 0 ]; then
	echo "Failed to read current directory"
	exit 1
fi

# nonexistent cgroup
cgm remove memory ooga2
cgm listchildren memory ooga2
if [ $? -eq 0 ]; then
	echo "Wrong result listing nonexistent directory"
	exit 1
fi

# empty cgroup
cgm create memory ooga
cgm listchildren memory ooga
if [ $? -ne 0 ]; then
	echo "Failed to list empty directory"
	exit 1
fi

exit 0
