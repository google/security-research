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


#set -e

source ../tools/utils.sh

declare zentool=../zentool

if ! test -x "${zentool}"; then
    logerr "zentool binary not available, try make"
    exit 1
fi

# The system ssh-agent is very slow, so I usually use ssh-agent.openssh for
# testing.
function find_ssh_agent()
{
    local path
    local -i agent

    # Find the pid of ssh-agent so we can guess the socket path.
    if ! agent=$(pgrep --oldest -f ssh-agent.openssh); then
        return 1
    fi

    # This seems like a good guess for the agent path.
    path=$(echo /tmp/ssh-*/agent.$((agent - 1)))

    # See if it makes sense
    if ! test -O "${path}" -a -S "${path}"; then
        logerr "the guessed socket path %s was not correct" "${path}"
        return 1
    fi

    export SSH_AUTH_SOCK="${path}"

    # Make sure it has some keys loaded
    if ! ssh-add -l > /dev/null; then
        logerr "agent may not be ready, try this: SSH_AUTH_SOCK=%s ssh-add" "${path}"
        return 1
    fi

    # Seems okay, it should be ready.
    return 0
}

# verify_output command --to --run
function verify_output()
{
    local cmd
    local golden="expected_output.txt"

    if ! diff -U8 -bu <("${@}")                      \
                 <(awk -v cmd="^%${*}$" '
                    $0 ~ cmd,/^%%/ {
                        if ($1 !~ /^%/) print
                    }' "${golden}"
                  ) >> error.${$}.diff; then
        logerr "ERR: %s" "${*}"
        logmsg "You can examine or accept the changes with:"
        logmsg "    patch -lRF3 expected_output.txt %s" error.${$}.diff
        return 1
    fi

    # Remove any unused result
    if test -e error.${$}.diff -a ! -s error.${$}.diff; then
        rm error.${$}.diff
    fi

    logmsg "OK: check %s" "${*}"
    return 0
}

# cksum_output "2142566903 49" command --to --run
function cksum_output()
{
    local cksum="${1}"
    local result
    shift

    if ! result=$("${@}" | cksum); then
        logerr "executing ${1} failed"
        return 1
    fi
    if test "${result}" != "${cksum}"; then
        logerr "ERR: %s" "${*}"
        return 1
    fi

    logmsg "OK: %s" "${*}"
    return 0
}

# insn_verify hostname insn regex input...
function insn_verify()
{
    local hostname="${1}"
    local insn
    local result
    local code="${2}"
    local regex="${3}"
    local match

    # Make sure that is safely quoted for ssh
    printf -v insn "%q" "${code}"

    shift 3

    if ! result=$(ssh ${hostname} zentool/scripts/testexec.sh "${insn}" "${@}"); then
        logerr "FAIL: [%s] %-26s => %s" "${hostname}" "${code}" "${result}"
        return 1
    fi

    if ! match=$(grep -oP "${regex}" <<< "${result}"); then
        logerr "ERR: [%s] %-27s => %s !~ /%s/" "${hostname}" "${code}" "${result}" "${regex}"
        return 1
    fi

    logmsg "OK: [%s] %-28s => %s ~ /%s/" "${hostname}" "${code}" "${match}" "${regex}"
    return 0
}

# get_ucode_revision hostname
function get_ucode_revision()
{
    local hostname="${1}"
    ssh "${hostname}" sudo rdmsr -p 2 -X -c 0x8b
}
