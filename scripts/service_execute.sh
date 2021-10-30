#!/bin/sh

script_dir="/etc/service.d"

cd ${script_dir}
for f in ${script_dir}/S*; do
    "$f" $1
done

