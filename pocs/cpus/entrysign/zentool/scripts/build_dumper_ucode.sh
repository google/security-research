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


# "ld rdi, 5:[rsi]" doesn't work in slot 2 (does work in slot 0)
./zentool --output=modified.bin edit --nop all --match all=0 --seq all=7 --match 0=@fpatan \
    --insn q0i0="xor rax,rax,rax" --insn q0i1="add rax,rax,0x1337" \
    --insn q1i0="ld rdi, $1:[rsi]" \
    --hdr-revlow 0x6 template.bin
    #--insn-field q1i0.class=$2 \
    #--insn q1i0=0xA86F3C140420942C --insn-field q1i0.reg1=0x16 --insn-field q1i0.reg2=0x17 --insn-field q1i0.0:1=$1 \

./zentool resign modified.bin

sudo ./zentool load --cpu=2 modified.bin