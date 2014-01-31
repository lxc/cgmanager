#!/bin/bash

echo "test 18: api_version"

dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgmanager/sock /org/linuxcontainers/cgmanager org.freedesktop.DBus.Properties.Get string:'org.linuxcontainers.cgmanager0_0' string:'api_version'
if [ $? -ne 0 ]; then
	echo "Error getting the api version"
	exit 1
fi
