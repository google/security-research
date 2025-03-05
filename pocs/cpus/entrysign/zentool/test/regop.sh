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


source testing.sh

if ! find_ssh_agent; then
    logerr "ssh-agent might not be ready"
    exit 1
fi

for host in $@; do
    insn_verify ${host} "add rax, rax, 0x123" =.4141414141414264 0x4141414141414141

    insn_verify ${host} "add.q rax, rax, rbx" =.ffffffffffffffff 0xfffffffffffffffe 0x1
    insn_verify ${host} "add.q rax, rax, rbx" =.0000000000000000 0xfffffffffffffffe 0x2
    # known broken, i dunno why
    #insn_verify ${host} "add.d rax, rax, rbx" =.ffffffff00000000 0xfffffffffffffffe 0x2
    insn_verify ${host} "add.w rax, rax, rbx" =.ffffffffffff0000 0xfffffffffffffffe 0x2
    insn_verify ${host} "add.b rax, rax, rbx" =.ffffffffffffff00 0xfffffffffffffffe 0x2
    insn_verify ${host} "add.q rax, rax, rbx" =.f+f$ 0x1234567890ABCDEF 0xEDCBA9876F543210
    insn_verify ${host} "add.q rax, rax, rbx" =.0+0$ 0x1234567890ABCDEF 0xEDCBA9876F543211
    insn_verify ${host} "add.q rax, rax, rbx" =.0+1$ 0x1234567890ABCDEF 0xEDCBA9876F543212

    insn_verify ${host} "sub rax, rax, rbx" =.a+b 0x5555555555555555 0xaaaaaaaaaaaaaaaa
    insn_verify ${host} "sub rax, rax, 42" =.a+80 0xaaaaaaaaaaaaaaaa

    insn_verify ${host} "popcnt rax, rax" =.0+20$ 0x0123456789ABCDEF
    insn_verify ${host} "popcnt rax, rax" =.0+40$ 0xFFFFFFFFFFFFFFFF
    insn_verify ${host} "popcnt rax, rax" =.0+00$ 0x0000000000000000
    insn_verify ${host} "popcnt.w rax, rax" =.f+0010$ 0xFFFFFFFFFFFFFFFF
    insn_verify ${host} "popcnt.q rax, rbx" =.0+20$ 0x5555555555555555 0xAAAAAAAAAAAAAAAA

    insn_verify ${host} "or rax, rax, 0x42" =.0+ff42 0xff00
    insn_verify ${host} "shl rax, rax, rbx" =.0+1fe 0xff 1

    insn_verify ${host} "xor rax, rax, rbx" =.f+$ 0x5555555555555555 0xaaaaaaaaaaaaaaaa
    insn_verify ${host} "xor rax, rax, rbx" =.0+$ 0x5555555555555555 0x5555555555555555
    insn_verify ${host} "xor rax, rax, rbx" =.[41]+$ 0x4040404040404040 0x0101010101010101
    insn_verify ${host} "xor rax, rax, rax" =.0+$ 0x0123456789ABCDEF
    insn_verify ${host} "xor.q rax, rax, rbx" =.0+$ 0 0
    insn_verify ${host} "xor.q rax, rax, rbx" =.0+1$ 0 1

    # nadd is (~arg1 + arg2)
    insn_verify ${host} "nadd rax, rax, rbx" =.bebebebed0f31536 0x4141414141414141 0x12345678
    insn_verify ${host} "nadd rax, rbx, rax" =.414141412f0ceac8 0x4141414141414141 0x12345678
    insn_verify ${host} "nadd.b rax, rax, 0xAA" =.4141414141414168 0x4141414141414141
    insn_verify ${host} " add.b rax, rax, 0xAA" =.41414141414141eb 0x4141414141414141

    insn_verify ${host} "ror rax, rax, 1" =.80+$ 1
    insn_verify ${host} "ror rax, rax, 1" =.f+$ 0xFFFFFFFFFFFFFFFF
    insn_verify ${host} "ror rax, rax, 4" =.14[14]+$ 0x4141414141414141
    insn_verify ${host} "ror rax, rax, 8" =.41[14]+$ 0x4141414141414141
    insn_verify ${host} "rol rax, rax, 8" =.41[14]+$ 0x4141414141414141
    insn_verify ${host} "rol rax, rax, 4" =.14[14]+$ 0x4141414141414141

    # nsub is ~(arg2 - arg1)
    insn_verify ${host} "nsub rax, rax, rbx" =.f+a 10 15
    insn_verify ${host} "nsub rax, rax, rbx" =.f+e 0 1
    insn_verify ${host} "nsub rax, rbx, rax" =.0+a 0xfffffffffffffffb 6

    # check flags
    insn_verify ${host} "add.qs rax, rbx, 1" flags.c..zS --flags 0 0xFFFFFFFFFFFFFFFE
    insn_verify ${host} "add.qs rax, rbx, 1" flags.C..Zs --flags 0 0xFFFFFFFFFFFFFFFF

    insn_verify ${host} "sub.sq rax, rax, 1" flags.C..zS --flags 0
    insn_verify ${host} "sub.sq rax, rax, 1" flags.c..Zs --flags 1

    insn_verify ${host} "ror.s rax, rax, 1" flags.C..zS --flags 1
    insn_verify ${host} "ror.s rax, rax, 1" flags.c..Zs --flags 0

    insn_verify ${host} "bswap.q rax, rax" =.efcdab9078563412 0x1234567890abcdef
    insn_verify ${host} "mov rax, rbx" =.[fe]+ 0x4141414141414141 0xfefefefefefefefe

    # Now check that the carry flag is honored.
    # add should totally ignore the carry flag, so the answer should be the same
    insn_verify ${host} "add.sq rax, rbx, 0" =.ffffffffffffffff --eflags 1 0 0xFFFFFFFFFFFFFFFF
    insn_verify ${host} "add.sq rax, rbx, 0" =.ffffffffffffffff --eflags 0 0 0xFFFFFFFFFFFFFFFF
    # adc should include the carry flag, so different answer
    insn_verify ${host} "adc.sq rax, rbx, 0" =.0000000000000000 --eflags 1 1 0xFFFFFFFFFFFFFFFF
    insn_verify ${host} "adc.sq rax, rbx, 0" =.ffffffffffffffff --eflags 0 0 0xFFFFFFFFFFFFFFFF
    # if we dont set the status bit, then CF is not copied to ECF, so should be the same
    insn_verify ${host} "adc.q rax, rbx, 0" =.ffffffffffffffff --eflags 1 0 0xFFFFFFFFFFFFFFFF
    insn_verify ${host} "adc.q rax, rbx, 0" =.ffffffffffffffff --eflags 0 0 0xFFFFFFFFFFFFFFFF

    # Now check the other flags work correctly, note that this is only reliable
    # after milan (for some reason)
    case ${host} in
        rome.cpu)       continue;;
        picasso.cpu)    continue;;
        naples.cpu)     continue;;
    esac

    insn_verify ${host} "add.bs rax, rax, rbx" flags.c..z. --flags 0 0xFF
    insn_verify ${host} "add.bs rax, rax, rbx" flags.C..Z. --flags 1 0xFF
    insn_verify ${host} "add.bs rax, rax, rbx" flags.C..z. --flags 2 0xFF

done
