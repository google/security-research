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


# val=0x4; for opcode in `seq $((0x0)) $((0xff))`; do printf "0x%02x 0x%x\n" $opcode $val; ./build_alu_ucode.sh $opcode $val >/dev/null &&  taskset -c 2 ./opcodes | grep -Ea "GPR\[13\]|FLAGS"; done |less -i
./zentool --output=modified.bin edit --nop all --match all=0 --seq all=7 --match 0=@fpatan \
    --insn q0i0="xor rax,rax,rax" --insn q0i1="add rax,rax,0x1337" \
    --insn q1i0="add r13,r13,$2" \
    --insn-field q1i0.type=$1 --insn-field q1i0.ss=1 \
    --hdr-revlow 0x6 template.bin

./zentool resign modified.bin

sudo ./zentool load --cpu=2 modified.bin