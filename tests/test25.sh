#!/bin/bash

echo "Test 25: gettasksrecursive"

cgm remove freezer z1 || true
cgm remove memory z1 || true

sleep 1

cgm create freezer z1/z2/z3
cgm create memory z1/z2/z3

sleep 200 &
p1=$!
sleep 200 &
p2=$!
sleep 200 &
p3=$!
sleep 200 &
p4=$!

cleanup() {
	kill -9 $p1 $p2 $p3 $p4 || true
}

trap cleanup EXIT

cgm movepid freezer z1/z2/z3 $p1
cgm movepid freezer z1/z2/z3 $p2
cgm movepid freezer z1/z2 $p3

cgm movepid memory z1/z2/z3 $p2
cgm movepid memory z1 $p3


list=`cgm gettasksrecursive freezer z1`
list2=`cgm gettasksrecursive memory z1`
list3=`cgm gettasksrecursive freezer z1/z2/z3`

n1=`echo "$list" | wc -l`
n2=`echo "$list2" | wc -l`
n3=`echo "$list3" | wc -l`

if [ $n1 -ne 3 ]; then
	echo "freezer:z1 had $n1 tasks"
	exit 1
fi
if [ $n2 -ne 2 ]; then
	echo "freezer:z2 had $n1 tasks"
	exit 1
fi
if [ $n3 -ne 2 ]; then
	echo "freezer:z3 had $n1 tasks"
	exit 1
fi

echo PASS
