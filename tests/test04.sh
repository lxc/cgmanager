#!/bin/bash

cgm getvalue memory xxx/b memory.usage_in_bytes
if [ $? -ne 0 ]; then
	exit 1
fi
exit 0
