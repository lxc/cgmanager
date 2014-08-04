#!/bin/bash

echo "test 18: api_version"

cgm apiversion
if [ $? -ne 0 ]; then
	echo "Error getting the api version"
	exit 1
fi
