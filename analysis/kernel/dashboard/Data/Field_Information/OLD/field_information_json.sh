#!/bin/bash

if [ -z "$1" ]
then
    echo -e '[ERROR] No vmlinux binarry supplied as an argument to a script!'
    exit 1
fi

if ! command -v pahole 2>&1 >/dev/null
then
    echo -e 'pahole could not be found'
    exit 1
elif ! command -v bpftool 2>&1 >/dev/null
then
    echo -e 'bpftool could not be found'
    exit 1
elif ! command -v jq 2>&1 >/dev/null
then
    echo -e 'jq could not be found'
    exit 1
elif ! command -v readelf 2>&1 >/dev/null
then
    echo -e 'readelf could not be found'
    exit 1
fi

(set -x; readelf -S $1 | grep -q debug > /dev/null)
if [ $? -eq 0 ]
then
    echo -e '[OK] readelf. DWARF information is in kernel'
else
    echo -e '[ERROR] no DWARF information found in kernel'
    exit 1
fi

(set -x; pahole --btf_encode_detached btf-$1 $1)
if [ $? -eq 0 ]
then
    echo -e '[OK] pahole. BTF dump'
else
    exit 1
fi

(set -x; bpftool btf dump -j file btf-$1 > btf-$1.json)
if [ $? -eq 0 ]
then
    echo -e '[OK] bpftool. BTF converted into json'
else
    echo -e '[ERROR] bpftool. Something went wrong'
    exit 1
fi

# Test querry
echo -e 'Test query results:'
(set -x; jq -c '.types[] | select(.kind=="STRUCT" and .size>64 and .size<=65)' btf-$1.json)

