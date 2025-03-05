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

# Which core you want to use for testing
declare -i core=2

# The template microcode file you want me to edit
declare microcode=template.bin

# The base instruction you want me to fuzz, I won't change except the field.
declare code="mov rax, rax, 0x41"

# The field name from insn you want me to fuzz"
declare field="ext"

# The output logfile
declare logfile=fieldscan.${HOSTNAME}.${field}.json

# No need to edit these
declare tmpfile=$(mktemp)
declare -i currev
declare -i newrev
declare -i insn
declare -i op
declare -i maxop=1

source tools/utils.sh

# Initialize output file
json_init_file ${logfile}

# Make sure the microcode file exists, my test scripts install one.
if ! test -f ${microcode}; then
    logerr "the template microcode file wasnt found, install one first"
    exit 1
fi

# Make sure we can parse that file correctly
if ! ./zentool print ${microcode} > ${tmpfile}; then
    logerr "failed to parse microcode header, is it valid?"
    exit 1
fi

# Verify sure it looks sane.
if grep -q '^Encrypted:.*true' ${tmpfile}; then
    logerr "microcode is encrypted, decrypt it first?"
    exit 1
fi

if grep -q '^Autorun:.*true' ${tmpfile}; then
    logerr "microcode has autorun flag, remove it first?"
    exit 1
fi

# Check that the instruction is valid
if ! insn=$(./mcas --quiet "${code}"); then
    logerr "the instruction '%s' didn't assemble" "${code}"
    exit 1
fi

# Determine next op to test
if ! op=$(json_first_unset ${logfile}); then
    logerr "failed to determine checkpoint status"
    exit 1
fi

# Discover the current microcode revision
currev=$(get_ucode_rev ${core})

# Verify that's a real field
if ! ./mcop --quiet --set ${field}=0 $(printf "%#x" ${insn}); then
    logerr "failed to set the field to zero, is it correct?"
    exit 1
fi

# Figure out the acceptable range
until ! ./mcop --quiet --set ${field}=${maxop} $(printf "%#x" ${insn}); do
    let "maxop <<= 1"
done

for ((; op < maxop; op++)); do
        # Already checked this value
        if json_get_code ${logfile} ${op}; then
            continue
        fi

        # Check if the microcode revision is too high to test
        if (((++currev & 0xff) == 0x00)); then
            logerr "the current microcode revision cant be incremented"
            sudo reboot; break
        fi

        # Mark this as failed, until we know otherwise
        json_set_code ${logfile} ${op} "failed"

        # Now generate a testcase
        ./zentool --output=${tmpfile} edit  --match all=0                                   \
                                            --nop   all                                     \
                                            --seq   0,1=7                                   \
                                            --match 0,1=@fpatan                             \
                                            --insn  q1i0=$((insn))                          \
                                            --insn-field q1i0.${field}=$((op))              \
                                            --hdr-revision ${currev}                        \
                                            ${microcode}
        # Fix the signature
        ./zentool fixup ${tmpfile}

        # Now notify the watchdog we're about to do something dangerous
        watchdog_reset

        # Load the microcode
        sudo ./zentool load --core=${core} ${tmpfile}

        # We can at least load it at this point.
        json_set_code ${logfile} ${op} "loaded"

        # Now query the current revision
        newrev=$(get_ucode_rev ${core})

        # We can at least run rdmsr on it
        json_set_code ${logfile} ${op} "queried"

        # Verify the update was applied
        if ((newrev != currev)); then
            sudo reboot; break
        fi

        # The core was successfully updated
        json_set_code ${logfile} ${op} "updated"

        # Now test the core
        if result=$(taskset -c ${core} ./mtalk 0); then
            json_set_code ${logfile} ${op} "${result:-complete}"
        else
            # Execution failed, but core still alive
            json_set_code ${logfile} ${op} "executed"
        fi
        sync
done
