#!/bin/bash

echo "Test 24: prune"

if [ -n "$SUDO_USER" ]; then
	gid=$SUDO_GID
	uid=$SUDO_UID
else
	gid=1000
	uid=1000
fi

cgm create freezer prune0/prune1/prune2

# Test that non-root cannot prune root-owned dir
if sudo -u \#$uid cgm prune freezer prune0; then
	echo "unpriv user was able to prune a root-owned cgroup"
	exit 1
fi

# Test that root can recursively prune
if ! cgm prune freezer prune0; then
	echo "root failed to prune a directory"
	exit 1
fi
sleep 1 # give buggy kernels a chance
if cgm listchildren freezer prune0 2>/dev/null; then
	echo "root failed to prune a directory"
	exit 1
fi

# Test that prune effects after all tasks die
cgm create freezer prune1
sleep 3 &
pid=$!
cgm movepid freezer prune1 $pid
cgm prune freezer prune1
wait $!
sleep 1 # give buggy kernels a chance
if cgm listchildren freezer prune1 2>/dev/null; then
	echo "prune failed to effect remove-on-empty"
	exit 1
fi

# Same, but recursive
# This will fail if cgroup has been premounted.  
cgm create freezer prune1/prune2
sleep 3 &
pid=$!
cgm movepid freezer prune1/prune2 $pid
cgm prune freezer prune1
wait $!
sleep 1 # give buggy kernels a chance
if cgm listchildren freezer prune1 2>/dev/null; then
	echo "prune failed to recursively remove-on-empty"
	echo "if freezer was not premounted, this is a bug"
	exit 1
fi

echo PASS
