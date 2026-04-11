#!/bin/bash
set -ex
mount -t proc none /proc
mount -t sysfs none /sys

mkdir /tmp/exp_ro
mount -t 9p exp /tmp/exp_ro

mkdir /tmp/exp
chown user:user /tmp/exp
chmod a+rx /tmp/exp

cp /tmp/exp_ro/* tmp/exp/
chmod a+rx /tmp/exp/*

# Set-up lo interface so that it's coherent with the live instance.
ifconfig lo 127.0.0.1 netmask 255.0.0.0 up

CMD="/tmp/exp/exploit"
if [[ " $* " == *" kaslr_leak=1 "* ]]; then
    KASLR_BASE=`head -n 1 /proc/kallsyms | cut -d " " -f1`
    CMD="$CMD $KASLR_BASE"
fi

echo "running exploit, cmd='$CMD', ::EXPLOIT OUTPUT FROM HERE::"
su user -c "$CMD"
