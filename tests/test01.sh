#!/bin/bash

echo "Test 1: getValue"

cgm getvalue memory '' memory.usage_in_bytes
if [ $? -ne 0 ]; then
	exit 1
fi
exit 0
