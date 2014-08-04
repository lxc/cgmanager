#!/bin/bash -x

kmaj=`awk -F. '{ print $1 '} /proc/sys/kernel/osrelease`
kmin=`awk -F. '{ print $2 '} /proc/sys/kernel/osrelease`
if [ $kmaj -eq 3 -a $kmin -eq 16 ]; then
	echo "skipping test 14 (Remove)"
	exit 0
fi

echo "Test 14 (Remove)"
cgm create memory xxx/bbb

cgm listchildren memory xxx | grep -q bbb
if [ $? -ne 0 ]; then
	echo "Error durign setup: memory:xxx/b was not created"
	exit 1
fi

# should fail - requires recursive delete
cgm remove memory xxx 0
if [ $? -eq 0 ]; then
	echo "non-recursive Remove of non-empty directory wrongly succeeded."
	exit 1
fi

cgm remove memory xxx
if [ $? -ne 0 ]; then
	echo "recursive remove of directory wrongly failed."
	echo "and here are the contents of memory:''"
	cgm listchildren memory ''
	echo "and here are the contents of memory:xxx"
	cgm listchildren memory xxx
	exit 1
fi

cgm create memory xxx/b
cgm remove memory xxx/bbb 0
if [ $? -ne 0 ]; then
	echo "Failed to remove an empty directory (xxx/b)."
	echo "and here are the contents of memory:''"
	cgm listchildren memory ''
	echo "and here are the contents of memory:xxx"
	cgm listchildren memory xxx
	exit 1
fi
exit 0
