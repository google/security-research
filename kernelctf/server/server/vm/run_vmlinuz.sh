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

usage() {
    echo "Usage: $0 <vmlinuz-path> [--workdir=<path>] [--mount=<outside>:<inside>[:<options>]] [--modules-path=<...>] [--custom-modules-tar=<...>] [--gdb] [--snapshot] [--no-rootfs-update] [--nokaslr] [--stdout-file=<path>] [--qemu-args=<args>] [--kernel-args=<args>] -- [<commands-to-run-in-vm>]" >&2;
    exit 1;
}

QEMU_ARGS=""
EXTRA_CMDLINE=""
WORKDIR=""
MOUNTS=()
ARGS=()
while [[ $# -gt 0 ]]; do
  case $1 in
    --workdir=*) WORKDIR="${1#*=}"; shift;;
    --mount=*) MOUNTS+=("${1#*=}"); shift;;
    --modules-path=*) MODULES_PATH="${1#*=}"; shift;;
    --custom-modules-tar=*) CUSTOM_MODULES_TAR="${1#*=}"; shift;;
    --stdout-file=*) STDOUT_FILE="${1#*=}"; shift;;
    --qemu-args=*) QEMU_ARGS="${1#*=}"; shift;;
    --kernel-args=*) EXTRA_CMDLINE=" ${1#*=}"; shift;;
    --no-rootfs-update) NO_ROOTFS_UPDATE=1; shift;;
    --snapshot) SNAPSHOT=1; shift;;
    --gdb) GDB=1; shift;;
    --nokaslr) NOKASLR=1; shift;;
    --as-root) AS_ROOT=1; shift;;
    --) # stop processing special arguments after "--"
        shift
        while [[ $# -gt 0 ]]; do ARGS+=("$1"); shift; done
        break
        ;;
    -*|--*) echo "Unknown option $1"; usage;;
    *) ARGS+=("$1"); shift;;
  esac
done
set -- "${ARGS[@]}"

VMLINUZ="$1"
COMMANDS_TO_RUN="${*:2}"

if [ -z "$VMLINUZ" ] ; then usage; fi

IS_TEMP_WORKDIR=0
if [ -z "$WORKDIR" ]; then
    WORKDIR=$(mktemp -d -t image_runner_XXXXXX)
    IS_TEMP_WORKDIR=1
else
    mkdir -p "$WORKDIR"
    WORKDIR=$(realpath "$WORKDIR")
fi
export WORKDIR

ROOTFS_DIR="$SCRIPT_DIR/rootfs"

echo_err() {
    echo "$@" 1>&2;
}

if [ "$NO_ROOTFS_UPDATE" == "" ]; then
    . $SCRIPT_DIR/update_rootfs_image.sh
fi

# ttyS0 (kernel messages) goes to stdout, ttyS1 (/output file) goes to $WORKDIR/output
SERIAL_PORTS="-serial mon:stdio -serial file:$WORKDIR/output"
if [ ! -z "$STDOUT_FILE" ]; then
    # ttyS0 (kernel messages) goes to STDOUT_FILE, ttyS1 (/output file) goes to stdout
    SERIAL_PORTS="-serial file:$STDOUT_FILE -serial stdio"
fi

if [ "$GDB" == "1" ]; then QEMU_ARGS+=" -s -S"; fi
if [ "$SNAPSHOT" == "1" ]; then QEMU_ARGS+=" -snapshot"; fi
if [ "$NOKASLR" == "1" ]; then EXTRA_CMDLINE+=" nokaslr"; fi
if [ "$AS_ROOT" == "1" ]; then EXTRA_CMDLINE+=" AS_ROOT=1"; fi

ABC=({a..z})
IDE_IDX=0
VIRTIO_IDX=0
HAS_SCSI_CTRL=0
MOUNT_PATHS_LIST=()

for M in "${MOUNTS[@]}"; do
    IFS=':' read -r OUTSIDE_PATH INSIDE_PATH OPTIONS <<< "$M"
    if [ -z "$OUTSIDE_PATH" ] || [ -z "$INSIDE_PATH" ] || [ ! -e "$OUTSIDE_PATH" ]; then
        echo_err "Error: Invalid mount: $M"
        usage
    fi

    if [[ "$OPTIONS" == *"unmap"* ]] || [[ "$OPTIONS" == *"scsi"* ]]; then
        DEV_NAME="/dev/sd${ABC[IDE_IDX]}"
        QEMU_ARGS+=" -drive file=$OUTSIDE_PATH,format=raw,if=ide,discard=on,snapshot=on,detect-zeroes=unmap"
        IDE_IDX=$((IDE_IDX+1))
    else
        DEV_NAME="/dev/vd${ABC[VIRTIO_IDX]}"
        VIRTIO_IDX=$((VIRTIO_IDX+1))
        QEMU_ARGS+=" -drive file=$OUTSIDE_PATH,if=virtio,format=raw,readonly=on"
    fi
    OPT_FLAG=""
    if [[ "$OPTIONS" == *"copy"* ]]; then
        OPT_FLAG=":copy"
    fi
    MOUNT_PATHS_LIST+=("$DEV_NAME:$INSIDE_PATH$OPT_FLAG")
done

if [ ${#MOUNT_PATHS_LIST[@]} -gt 0 ]; then
    EXTRA_CMDLINE+=" MOUNT_PATHS=$(IFS=,; echo "${MOUNT_PATHS_LIST[*]}")"
fi

if [ ! -z "$MODULES_PATH" ]; then
    if [[ "$MODULES_PATH" == */ ]]; then MODULES_PATH=${MODULES_PATH%/}; fi
    if [[ -f "$MODULES_PATH" ]]; then
        MODULES_IMG="$MODULES_PATH"
    elif [[ -f "$MODULES_PATH.img" ]]; then
        MODULES_IMG="$MODULES_PATH.img"
    elif [[ -f "$MODULES_PATH/modules.img" ]]; then
        MODULES_IMG="$MODULES_PATH/modules.img"
    else
        MODULES_IMG="$WORKDIR/modules.img"
        check_archive_uptodate "$MODULES_IMG" "$MODULES_PATH" "virt-make-fs --type ext4 --size=+16M '$MODULES_PATH' '$MODULES_IMG'"
    fi
    QEMU_ARGS+=" -drive file=$MODULES_IMG,if=ide,format=raw,snapshot=on"
    EXTRA_CMDLINE+=" MOUNT_MODULES=/dev/sd${ABC[IDE_IDX]}"
    IDE_IDX=$((IDE_IDX+1))
fi

if [ ! -z "$CUSTOM_MODULES_TAR" ]; then
    QEMU_ARGS+=" -drive file=$CUSTOM_MODULES_TAR,if=ide,format=raw,snapshot=on"
    EXTRA_CMDLINE+=" MOUNT_CUSTOM_MODULES=/dev/sd${ABC[IDE_IDX]}"
    IDE_IDX=$((IDE_IDX+1))
fi

stdbuf -o0 qemu-system-x86_64 -m 5G -nographic -nodefaults -no-reboot \
    -enable-kvm -cpu host,-la57 -smp cores=2 -overcommit mem-lock=on -mem-prealloc \
    -kernel $VMLINUZ \
    -initrd $WORKDIR/initramfs.cpio \
    -nic user,model=virtio-net-pci \
    $SERIAL_PORTS $QEMU_ARGS \
    -append "console=ttyS0 panic=-1 oops=panic loadpin.enable=0 loadpin.enforce=0$EXTRA_CMDLINE init=/init -- $COMMANDS_TO_RUN"

stty sane 2>/dev/null || true

if [ "$IS_TEMP_WORKDIR" == "1" ]; then
    rm -rf "$WORKDIR" 2>/dev/null || true
fi
