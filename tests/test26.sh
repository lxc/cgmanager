#!/bin/bash

echo "Test 25: listkeys"

cgm remove memory listkeys1 || true

sleep 1

cgm create memory listkeys1
cgm chown memory listkeys1 100000 100000

output=$(cgm listkeys memory listkeys1)

id1=$(echo "$output" | awk '/^tasks/ { print $2 }')
if [ "$id1" != "100000" ]; then
	echo "Bad listkeys output"
	exit 1
fi

echo PASS
