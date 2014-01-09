#!/bin/bash

# Try to move myself task to xxx/b - should work
# (useless though since movepid, not its caller, will be moved)
echo "Test 8 (movepid self)"
movepid -c memory -n xxx/b > /dev/null 2>&1
if [ $? -ne 0 ]; then
	exit 1
fi

exit 0
