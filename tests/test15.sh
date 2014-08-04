#!/bin/bash

ret=0
echo "Test 14 (nrtasks)"

cgm create memory xxx/c

sleep 200 &
pid=$!

cgm movepid memory xxx/c $pid

result=`cgm gettasks memory xxx/c`

if [ "$result" != "$pid" ]; then
	echo "result is $result not $pid"
	ret=1
fi

kill -9 $pid 2>&1 > /dev/null

cgm remove memory xxx/c

exit $ret
