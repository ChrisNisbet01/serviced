#!/bin/sh

i=0
while [ $i -lt $1 ]; do
    echo "$(date)" >> /home/chris/projects/serviced/out.txt
    echo "to stdout and count is $i args $@"
    echo "to stderr and count is $i" >&2
    sleep 1
    i=$((i + 1))
done
