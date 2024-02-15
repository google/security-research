#!/bin/bash
echo running!

cd /home/poprdi
socat ssl-l:1337,reuseaddr,fork,cert=server_cert_and_key.pem,verify=0,openssl-min-proto-version=tls1.3 exec:"nsjail/nsjail --chroot / --user 99999 --group 99999 --disable_clone_newnet --rlimit_cpu 1800 -T /tmp/ -- /usr/bin/timeout 1800 /home/poprdi/server.py"
