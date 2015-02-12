#!/bin/bash

echo "Test 26: getvalue of siblings"

cgm remove memory sibling || true
cgm remove memory sibling1 || true

sleep 1

cur=`cgm getpidcgroupabs memory $$`
cgm create memory sibling
cgm create memory sibling1

cgm movepid memory sibling $$
failed=0
cgm getvalue memory ${cur}/sibling1 memory.limit_in_bytes && failed=1 || true
if [ $failed -eq 1 ]; then
	echo "Fail: able to read sibling values"
	exit 1
fi

echo PASS
