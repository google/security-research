#!/bin/bash
if [ $# -ne 4 ] && [ $# -ne 3 ]; then
  echo "Usage: $0 <release_path> <flag_fn> <init> [<capabilities>]"
  exit 1
fi

RELEASE_PATH=$1
FLAG_FN=$2
INIT=$3
CAPABILITIES=$4
RELEASE=$(basename "$RELEASE_PATH")

HARDENING=""
if [[ "$RELEASE" == "mitigation-"* ]]; then
  HARDENING="sysctl.kernel.dmesg_restrict=1 sysctl.kernel.kptr_restrict=2 sysctl.kernel.unprivileged_bpf_disabled=2 sysctl.net.core.bpf_jit_harden=1 sysctl.kernel.yama.ptrace_scope=1 slab_virtual=1 slab_virtual_guards=1";
elif [[ $(date +%Y-%m-%d) > "2025-02-28" ]]; then
  HARDENING="sysctl.net.core.bpf_jit_harden=2"
fi

IO_URING="sysctl.kernel.io_uring_disabled=2"
USERNS="sysctl.user.max_user_namespaces=1"

if [[ -n "$CAPABILITIES" ]]; then
  for element in $(echo "$CAPABILITIES" | tr ',' '\n'); do
    if [[ "$element" == "io_uring"* ]]; then
      IO_URING=""
    elif [[ "$element" == "userns"* ]]; then
      USERNS=""
    fi
  done
fi

exec qemu-system-x86_64 -m 3.5G -nographic -no-reboot \
  -monitor none \
  -enable-kvm -cpu host -smp cores=2 \
  -kernel $RELEASE_PATH/bzImage \
  -initrd ramdisk_v1.img \
  -nic user,model=virtio-net-pci \
  -drive file=rootfs_v3.img,if=virtio,cache=none,aio=native,format=raw,discard=on,readonly \
  -drive file=$FLAG_FN,if=virtio,format=raw,readonly \
  -append "console=ttyS0 root=/dev/vda1 rootfstype=ext4 rootflags=discard ro $HARDENING $USERNS $IO_URING init=$INIT hostname=$RELEASE"
