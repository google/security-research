#!/bin/bash
set -e

usage() {
    echo "Usage: $0 <release-name> [--root]";
    exit 1;
}

INIT_FN="/home/user/run.sh"

ARGS=()
while [[ $# -gt 0 ]]; do
  case $1 in
    --root) INIT_FN="/bin/bash"; shift;;
    -*|--*) echo "Unknown option $1"; exit 1;;
    *) ARGS+=("$1"); shift;;
  esac
done
set -- "${ARGS[@]}"

RELEASE_NAME="$1"
if [ -z "$RELEASE_NAME" ]; then usage; fi

if [ ! -f "qemu_v3.sh" ]; then wget https://storage.googleapis.com/kernelctf-build/files/qemu_v3.sh; fi
chmod u+x qemu_v3.sh

if [ ! -d "releases/$RELEASE_NAME" ]; then mkdir -p "releases/$RELEASE_NAME"; fi
if [ ! -f "releases/$RELEASE_NAME/bzImage" ]; then
    wget -O "releases/$RELEASE_NAME/bzImage" "https://storage.googleapis.com/kernelctf-build/releases/$RELEASE_NAME/bzImage"
fi

if [ ! -f "rootfs_v3.img" ]; then
    wget https://storage.googleapis.com/kernelctf-build/files/rootfs_v3.img.gz
    gzip -d rootfs_v3.img.gz
fi

if [ ! -f "ramdisk_v1.img" ]; then wget https://storage.googleapis.com/kernelctf-build/files/ramdisk_v1.img; fi
if [ ! -f "flag" ]; then echo "kernelCTF{example_flag}" > flag; fi

exec ./qemu_v3.sh "releases/$RELEASE_NAME" flag "$INIT_FN"