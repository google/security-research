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

if ! find_ssh_agent; then
    logerr "ssh-agent might not be ready"
    exit 1
fi

for host in $@; do
    declare ucode=$(get_ucode_revision ${host})
    declare main=$(ssh ${host} nm zentool/mtalk | grep -Po '^0+\K.*(?= T main$)')
    declare magic=$(ssh ${host} nm zentool/mtalk | grep -Po '^0+\K.*(?= d magic$)')
    declare message=$(ssh ${host} nm zentool/mtalk | grep -Po '^0+\K.*(?= T unreachable$)')

    # Revision should be lowercase
    ucode=${ucode,,}

    # check the microcode revision msr
    insn_verify ${host} "ld.q rax, ms:[rax]" =.0+${ucode:2:-2}ff$ 0x262

    # check alternate syntaxes also work
    insn_verify ${host} "ld rax, 5:[rax+rbx]" =.0+${ucode:2:-2}ff$ 0x200 0x62
    insn_verify ${host} "ld.d rax, ms:[rbx+0x62]" =.0+${ucode:2:-2}ff$ 0x1337 0x200

    # check return address is there
    insn_verify ${host} "ld.q rax, ls:[rbp+8]" =.0+${main:0:-3}...$ 0

    # check reading memory
    insn_verify ${host} "ld.q rax, ls:[rax]" =.5345435245543432 @magic
    insn_verify ${host} "ld.d rax, ls:[rax]" =.0000000045543432 @magic

    # need to work on store support
    case ${host} in
        rome.cpu)       continue;;
        picasso.cpu)    continue;;
        naples.cpu)     continue;;
    esac

    # check stores
    insn_verify ${host} "ld.p [rax], rbx" =.0+${magic} @magic 0x4142434445464748
    insn_verify ${host} "ld.pq [rax], rbx" magic.*4142434445464748 @magic 0x4142434445464748
    insn_verify ${host} "ld.pd [rax], rbx" magic.*5345435241414141 @magic 0x4141414141414141

    # clobber revision msr
    insn_verify ${host} "ld.p ms:[rax], rbx" =.0+262 0x262 0x41424344

    # check that worked
    if ! test $(get_ucode_revision ${host}) == 0x41424344; then
        logerr "ERR: failed to change ucode revision"
    fi

    # put it back the way it was
    insn_verify ${host} "ld.p ms:[rax], rbx" =.0+262 0x262 ${ucode}
    # confirm that worked
    insn_verify ${host} "ld.q rax, ms:[rax]" =.0+${ucode:2:-2}ff$ 0x262

    # patch the return address?
    insn_verify ${host} "ld.pq ls:[rbp+8], rax" unreachable 0x${message}
done
