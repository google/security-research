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
declare microcode=data/cpu00860F01_ver08600102_2019-11-17_444C1A3D.bin
declare tmpfile=$(mktemp)
declare logfile=seqword.json
declare -i currev
declare -i newrev
declare -i core=2
declare -i mr


source tools/utils.sh

# The current microcode revision
declare -i currev=$(get_ucode_rev ${core})

# Initialize output file
json_init_file ${logfile}

if ! taskset -c ${core} ./opcodes; then
    logerr "the testcase didnt work before ucode applied"
    return 1
fi

# Determine next mr to test
if ! mr=$(json_first_unset ${logfile}); then
    logerr "failed to determine checkpoint status"
    return 1
fi

for ((; mr <= 0x1fff; mr++)); do
        # Already checked this value
        if json_get_code ${logfile} ${mr}; then
            continue
        fi

        # Check if the microcode revision is too high to test
        if (((++currev & 0xff) == 0x00)); then
            logerr "the current microcode revision cant be incremented"
            sudo reboot; break
        fi

        # Mark this as failed, until we know otherwise
        json_set_code ${logfile} ${mr} "failed"

        # Now generate a testcase
        ./zentool --output=${tmpfile} edit  --match all=0                           \
                                            --nop   all                             \
                                            --match 0,1=@fpatan                     \
                                            --seq   0,1=$((0x00000000 | mr))        \
                                            --insn  0,4="mov.q rax, rax, 0x1337"    \
                                            --hdr-revision ${currev}                \
                                            ${microcode}
        # Fix the signature
        ./zentool fixup ${tmpfile}

        # Now notify the watchdog we're about to do something dangerous
        watchdog_reset

        # Load the microcode
        sudo ./zentool load --core=${core} ${tmpfile}

        # We can at least load it at this point.
        json_set_code ${logfile} ${mr} "loaded"

        # Now query the current revision
        newrev=$(get_ucode_rev ${core})

        # We can at least run rdmsr on it
        json_set_code ${logfile} ${mr} "queried"

        # Verify the update was applied
        if ((newrev != currev)); then
            sudo reboot; break
        fi

        # The core was successfully updated
        json_set_code ${logfile} ${mr} "updated"

        # Now test the core
        if result=$(taskset -c ${core} ./opcodes); then
            json_set_code ${logfile} ${mr} "${result:-complete}"
        else
            # Execution failed, but core still alive
            json_set_code ${logfile} ${mr} "executed"
        fi
done
