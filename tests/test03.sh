#!/bin/bash

echo "Test 3 (Create)"
cgm create memory xxx/b
if [ $? -ne 0 ]; then
	exit 1
fi
exit 0
