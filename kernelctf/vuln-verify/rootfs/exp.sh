#!/bin/sh
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

set -e
ifconfig lo 127.0.0.1 netmask 255.0.0.0 up

if [ -e /flag ]; then rm /flag; fi
echo "CTF{secret_flag_deadbeef}" > /flag
chmod 0000 /flag

if [ -e /dev/xdk ]; then
    chmod o+rw /dev/xdk
fi
chmod o+rx /exp

chmod -R o+rx /bin /etc /usr /lib64

mkdir /tmp/exp
chmod 777 /tmp/exp
cp /exp /tmp/exp/exploit

echo "Running id and then the exploit: /exp $@"
ARG="id; /exp $@"
su user -c /bin/sh -c "$ARG"
