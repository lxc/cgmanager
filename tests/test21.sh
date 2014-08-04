#!/bin/bash

echo "Test 21: remove_on_empty"

if [ ! -f /run/cgmanager/agents/cgm-release-agent.memory ]; then
	echo "memory cgroup was premounted;  skipping remove_on_empty test"
	exit 0;
fi
if [ ! -f /run/cgmanager/agents/cgm-release-agent.devices ]; then
	echo "devices cgroup was premounted;  skipping remove_on_empty test"
	exit 0;
fi

cg="test21_cg"
cgm remove memory $cg
cgm remove devices $cg
cgm create memory $cg
cgm create devices $cg
sleep 200 &
pid=$!
cgm movepid memory $cg $pid
cgm movepid devices $cg $pid

cgm removeonempty memory $cg

kill $pid

# now $cg should be deleted in memory, but not in devices
# note if logind or upstart has set this for us then this will raise a false positive
cgm gettasks devices $cg
if [ $? -ne 0 ]; then
	echo "Remove-on-empty affected another cgroup"
	exit 1
fi

cgm gettasks memory $cg
if [ $? -eq 0 ]; then
	# Maybe we're on a slow vm.  Kernel needs time to spawn the remove
	# helper.  Give it some time...
	sleep 5
	cgm gettasks memory $cg
	if [ $? -eq 0 ]; then
		echo "Failed to remove-on-empty"
		exit 1
	fi
fi

echo "Test 21 (remove_on_empty) passed"
exit 0
