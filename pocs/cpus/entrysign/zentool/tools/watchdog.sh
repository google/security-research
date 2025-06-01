#!/bin/bash
# Copyright 2025 Google LLC
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

#
# This is a quick script for managing a USB watchdog device, mine looks like this:
#
# Bus 003 Device 019: ID 1a86:7523 QinHeng Electronics CH340 serial converter
#
# I bought it for $2 on AliExpress. I use this when trying to brute force
# parameters that might halt the CPU so badly it can't recover.
#

declare device=/dev/ttyUSB0

# The host we want to monitor
declare interface=enx00e04c68043c
declare host=192.168.2.10

# Time between health checks in seconds
declare -i interval=60

# If the host is dead, decrease checking interval to rapidly detect recovery.
declare -i deadint=2

# Maximum amount of time permitted between successful health checks in seconds.
declare -i timeout=300

# The watchdog wants 10 second increments, so divide that by 10
let timeout/=10

function rawbyte() {
    eval printf $(printf '\\\\x%02x' ${1})
}

# Open the watchdog interface
if ! exec 3<> ${device}; then
    printf "failed to open %s, wrong path?\n" ${device}
    exit 1
fi

# setup initial timeout
rawbyte ${timeout} >&3

if ! stty 9600 raw -echo <&3 ; then
    printf "failed to setup watchdog device\n"
    exit 1
fi

printf "%s: watchdog started, host %s, timeout %d...\n" "$(date +%H:%M)" "${host}" ${timeout}

while true; do
    # delay between checking host
    sleep ${interval}

    # check if host is alive
    for ((i = 0;; i += deadint)); do
        if ping -W 1 -q -c 1 -I ${interface} ${host} > /dev/null; then
            printf "%s: host is alive, resetting watchdog...\n" "$(date +%H:%M)"
            rawbyte ${timeout} >&3
            break
        fi
        # Interval is decreased while host is dead...
        printf "%s: host has been dead for %d seconds...\n" "$(date +%H:%M)" ${i}
        sleep ${deadint}
    done
done
