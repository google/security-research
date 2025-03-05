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
# Various utility functions useful when testing microcode
#

# Always sync on startup
sync

function logmsg()
{
    printf "${@}" >&1
    printf "\n"   >&1
}

function logerr()
{
    printf "${@}" >&2
    printf "\n"   >&2
}

# usage: get_ucode_rev <core>
function get_ucode_rev()
{
    sudo rdmsr -c -p ${core} 0x8b
}

# usage: json_get_code file code
function json_get_code()
{
    local hexstr
    printf -v hexstr "%04x" "${2}"

    jq -e --arg code "${hexstr}" '.[$code]' "${1}"
}

# usage: json_get_code file code status
function json_set_code()
{
    local tmpfile=$(mktemp)
    local hexstr

    printf -v hexstr "%04x" "${2}"

    if jq -e --arg code "${hexstr}" --arg status "${3}" '.[$code]=$status' ${1} > ${tmpfile}; then
        mv ${tmpfile} ${1}
    fi

    sync --data ${1}
}

# usage: json_init_file
function json_init_file()
{
    if ! test -e "${1}"; then
        printf "{}" > "${1}"
    fi
}

# usage: json_first_unset file
function json_first_unset()
{
    # Make an array of [1 .. last + 1], add it to the input and find the first non-duplicated value
    # This is hacky, must be a better way.
    jq -e '[
                keys[] | ascii_downcase | reduce explode[] as $n (0; . * 16 + ($n - 48) % 39)
           ] as $hex | $hex + [
                range(0; $hex | sort | last + 2)
           ] | group_by(.)
             | map(select(length == 1))
             | flatten
             | first' "${1}"
}

function watchdog_reset()
{
    if ! sudo pkill -x -USR1 uwatchdog; then
        echo "watchdog not available" 1>&2
    fi
}

function watchdog_cancel()
{
    if ! sudo pkill -x -USR2 uwatchdog; then
        echo "watchdog not available" 1>&2
    fi
}
