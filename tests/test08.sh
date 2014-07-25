#!/bin/bash

# Try to move myself task to xxx/b - should work
echo "Test 8 (movepid self)"
cgm create memory xxx/b

cgm movepid memory xxx/b $$
if [ $? -ne 0 ]; then
	exit 1
fi

exit 0
