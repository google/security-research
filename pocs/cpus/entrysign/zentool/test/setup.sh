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


set -e
source testing.sh

# I use ssh-agent.openssh to automate logins, make sure it's running
if ! find_ssh_agent; then
    logerr "unable to automate logins, run ssh-agent.openssh"
    exit 1
fi

# Make sure the binaries are up to date.
for host in $@; do
    logmsg "[*] Setting up host %s..." ${host}

    logmsg "\tSyncing..." ${host}
    make --silent -C .. sync HOST=${host}

    logmsg "\tRebuilding..." ${host}
    ssh ${host} make -j8 --silent -C zentool distclean
    ssh ${host} make -j8 --silent -C zentool all
    ssh ${host} make -j8 --silent -C zentool template.bin

    logmsg "\tChecking..." ${host}

    # Verify the host is setup correctly
    test $(ssh ${host} cat /sys/devices/system/cpu/isolated) -eq 2
    ssh ${host} grep -Eq "'\<nokaslr\>'" /proc/cmdline
    ssh ${host} grep -Eq "'\<nosmt\>'" /proc/cmdline
    ssh ${host} zentool/zentool --quiet version > /dev/null
    ssh ${host} zentool/mtalk --quiet --version > /dev/null

    logmsg "\tDone."
done
