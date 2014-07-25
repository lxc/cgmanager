#!/bin/bash

echo "Test 5 (../ getValue)"
#This should fail:
# Note, if ../xxx0123/b exists, it'll succeed and the test will report failure
cgm getvalue memory ../xxx0123/b memory.usage_in_bytes
if [ $? -eq 0 ]; then
	exit 1
fi
exit 0
