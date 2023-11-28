#!/bin/bash

set -ex

cat reptar.log

sudo mount -t debugfs none /sys/kernel/debug
echo 1 | sudo tee /sys/kernel/debug/mce/fake_panic
echo 0 | sudo tee /proc/sys/kernel/watchdog
echo 0 | sudo tee /proc/sys/kernel/printk_ratelimit
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
echo 0 | sudo tee /sys/bus/cpu/devices/cpu15/online

touch reptar.mce.asm
make reptar.mce.out || true

for i in {1..10}; do
    echo $i | tee reptar.log
    sudo sync
    sleep 0.3s
    taskset -c 7 ./reptar.mce.out &
    sleep 1s
    sudo dmesg -t | grep mce: | uniq -c | tee -a reptar.log
    sudo cat /sys/kernel/debug/mce/severities-coverage | grep -v $'^0\t' | tr '\n' , | tr '\t' : | tee -a reptar.log
    kill -9 %1 || true
done
