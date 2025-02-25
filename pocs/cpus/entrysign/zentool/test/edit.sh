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

declare template=../data/cpu00860F01_ver08600109_2022-03-28_DA3355E7.bin
declare tmpfile=$(mktemp)
declare -i mrcount
declare -i rdtsccount
declare mr
declare mr

cp "${template}" "${tmpfile}"

# How many match registers are there?
mrcount=$(../zentool --verbose print -m "${tmpfile}" | grep -cP '^\s+\[\d+\s?\]\s')

# check every match register can be set
for ((i = 0; i < mrcount; i++)); do
    ../zentool edit --match ${i}=@rdtsc ${tmpfile}
done

# They should all now be @rdtsc
rdtsccount=$(../zentool --verbose print -m "${tmpfile}" | grep -cP '^\s+\[\d+\s?\]\s....\s@rdtsc')

test ${rdtsccount} -eq ${mrcount}

logmsg "OK: edit: %u match register slots verified" ${mrcount}

# Now verify we can set some valid values
for ((i = 0; i < 13; i++)); do
    ../zentool edit --match 0=$(((1 << i) - 0)) ${tmpfile}
    # Read that value back
    mr=$(../zentool --verbose print -m ${tmpfile} | grep -Po '^\s+\[0\s\]\s\K....')
    test $((16#${mr})) -eq $(((1 << i) - 0))
done

for ((i = 0; i < 14; i++)); do
    ../zentool edit --match 0=$(((1 << i) - 1)) ${tmpfile}
    # Read that value back
    mr=$(../zentool --verbose print -m ${tmpfile} | grep -Po '^\s+\[0\s\]\s\K....')
    test $((16#${mr})) -eq $(((1 << i) - 1))
done

logmsg "OK: edit: match register ranges verified"

rm -f ${tmpfile}
