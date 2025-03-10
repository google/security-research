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
declare microcode=template.bin
declare tmpfile=$(mktemp)
declare -i core=2

# Make sure execution location is consistent
cd "$(dirname $0)"
cd ..

source tools/utils.sh

if ! test -f "${microcode}"; then
    logerr "Place a microcode file called %s for this cpu to use this script" "${microcode}"
    exit 1
fi

./zentool --output=${tmpfile}  edit --nop all                       \
                                    --hdr-revlow 0xff               \
                                    --match all=0                   \
                                    --match 0,1=@fpatan             \
                                    --seq   0,1=7                   \
                                    --insn  q1i0="${1}"             \
                                    ${microcode}
./zentool --output=${tmpfile} resign ${tmpfile}

# Notify watchdog we're about to do something dangerous.
watchdog_reset

sudo ./zentool --quiet load --cpu=${core} ${tmpfile}

# Discard opcode
shift

# Pass anything remaining to mtalk
setarch -R taskset -c ${core} ./mtalk "${@:---test}"

# Core still seems healthy, reset watchdog.
watchdog_cancel
