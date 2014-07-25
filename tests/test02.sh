#!/bin/bash

echo "Test 2 (getMyCgroup)"
cgm getpidcgroup memory $$
if [ $? -ne 0 ]; then
	exit 1
fi
exit 0
