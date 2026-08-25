#!/bin/bash
# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e

SCRIPT_DIR=$(dirname $(realpath "$0"))
ROOTFS_DIR="$SCRIPT_DIR/rootfs"
ROOTFS_IMG="rootfs.img"
ROOTFS_TAR="rootfs.tar"
WORKDIR="${WORKDIR:-$SCRIPT_DIR}"
INITRAMFS="$WORKDIR/initramfs.cpio"

echo_err() {
    echo "$@" 1>&2;
}

check_archive_uptodate() {
    local target="$1"
    local src="$2"
    local cmd="$3"
    if [ ! -f "$target" ] || [ "$src" -nt "$target" ]; then
        eval "$cmd"
    fi
}

download_busybox_if_missing() {
    if [ ! -f "$ROOTFS_DIR/busybox" ]; then
        echo_err "busybox was not found in the rootfs folder, downloading it..."
        # source: https://busybox.net/downloads/busybox-1.35.0.tar.bz2, binary: https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox
        curl -f https://storage.googleapis.com/kernel-research/files/busybox-1.35.0-x86_64-linux-musl -o "$ROOTFS_DIR/busybox"
        chmod a+rx "$ROOTFS_DIR/busybox"
    fi
}

regenerate_initramfs() {
    download_busybox_if_missing
    pushd "$ROOTFS_DIR" > /dev/null
    rm -f "$INITRAMFS" 2>/dev/null || true
    find . ! -name 'guestfish*' -print0 | cpio --owner 0:0 --null -ov --format=newc > "$INITRAMFS" 2>/dev/null
    popd > /dev/null
}

pushd "$SCRIPT_DIR" >/dev/null
regenerate_initramfs
popd >/dev/null
