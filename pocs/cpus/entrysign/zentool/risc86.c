/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <ctype.h>
#include <err.h>

#include "ucode.h"
#include "risc86.h"
#include "util.h"

char zen_size_to_suffix(uint8_t size)
{

    switch (size) {
        case 0: return 'b';
        case 1: return 'w';
        case 2: return 'd';
        case 3: return 'q';
    }

    errx(EXIT_FAILURE, "cannot translate %u to size suffix", size);

    return 0;
}

int zen_string_to_segment(const char *segment)
{
    char *end;
    int num;

    dbgmsg("decoding segment specified %s", segment);

    // The syntax 0x123:[rax] is acceptable
    num = strtoul(segment, &end, 0);

    if (*segment != 0 && *end == 0) {
        dbgmsg("segment %s appears to be numeric, thats okay", segment);
        return num;
    }

    // Okay, it must be symbolic then
    if (!segment || !segment[0] || segment[1] != 's')
        goto error;

    if (segment[0] == 't' || segment[0] == 'o') {
        // ts1, os3, etc.
        if (!isdigit(segment[2]))
            goto error;
    }

    // This is based on the table from US6336178B1
    switch (*segment) {
        case 'l': return SEG_LS;
        case 'm': return SEG_MS;
        case 'p': return SEG_PS;
        case 'v': return SEG_VS;
        //case 'e': return 0b0000; // ES architectural segment register
        //case 'c': return 0b0001; // CS architectural segment register
        //case 's': return 0b0010; // SS architectural segment register
        //case 'd': return 0b0011; // DS architectural segment register
        //case 'f': return 0b0100; // FS architectural segment register
        //case 'g': return 0b0101; // GS architectural segment register
        //case 'h': return 0b0110; // HS temporary segment register
        //case 'r': return 0b0111; // — (reserved)
        //case 't': return 0b1000 + segment[2] - '0'; // TS descriptor table SegReg (GDT or LDT)
        //case 'l': return 0b1010; // LS linear SegReg (ie, null segmentation)
        //case 'o': return 0b1100 + segment[2] - '0'; // OS effective (arch.) data segment register
    }

  error:
    errx(EXIT_FAILURE, "the specified segment %s was not valid", segment);
    return -1;
}

const char *zen_segment_to_string(zen_seg_t segment)
{
    static char segliteral[32];
    static const char *segnames[32] = {
        [SEG_LS] = "ls",
        [SEG_MS] = "ms",
        [SEG_PS] = "ps",
        [SEG_VS] = "vs",
    };

    if (segment > 0b1111)
        return "<bad>";

    if (segnames[segment] == NULL) {
        dbgmsg("no name for segment %u, using numeric constant", segment);
        snprintf(segliteral, sizeof segliteral, "%u", segment);
        return segliteral;
    }

    return segnames[segment];
}


const char *zen_reg_to_string(zen_reg_t reg)
{
    static char regliteral[32];
    static const char *regnames[REG_LAST] = {
        [REG_RAX] = "rax",
        [REG_RCX] = "rcx",
        [REG_RDX] = "rdx",
        [REG_RSI] = "rsi",
        [REG_RBX] = "rbx",
        [REG_RSP] = "rsp",
        [REG_RBP] = "rbp",
        [REG_RDI] = "rdi",
        [REG_R8 ] = "r8",
        [REG_R9 ] = "r9",
        [REG_R10] = "r10",
        [REG_R11] = "r11",
        [REG_R12] = "r12",
        [REG_R13] = "r13",
        [REG_R14] = "r14",
        [REG_R15] = "r15",
    };

    if (reg >= REG_LAST)
        return "<bad>";

    if (regnames[reg] == NULL) {
        dbgmsg("no name for register %u, using numeric constant", reg);
        snprintf(regliteral, sizeof regliteral, "reg%u", reg);
        return regliteral;
    }

    return regnames[reg];
}

int zen_string_to_reg(const char *name)
{
    dbgmsg("decoding register specified %s", name);

    for (int i = 0; i < UINT8_MAX; i++) {
        if (strcmp(zen_reg_to_string(i), name) == 0) {
            return i;
        }
    }

    errx(EXIT_FAILURE, "unrecognised register '%s' encountered", name);
}

const char *zen_opcode_to_string(zen_opclass_t opclass, uint8_t opcode)
{
    static const char * reg_mnemonics[256] = {
        [OP_NSUB]   = "nsub",
        [OP_AND]    = "and",
        [OP_SHL]    = "shl",
        [OP_BLL]    = "bll",
        [OP_ROL]    = "rol",
        [OP_RLC]    = "rlc",
        [OP_RRD]    = "rrd",
        [OP_SRC]    = "src",
        [OP_SHR]    = "shr",
        [OP_ROR]    = "ror",
        [OP_RRC]    = "rrc",
        [OP_SRD]    = "srd",
        [OP_SUB]    = "sub",
        [OP_SBB]    = "sbb",
        [OP_NADD]   = "nadd",
        [OP_ADC]    = "adc",
        [OP_ADD]    = "add",
        [OP_ADD2]   = "add2",
        [OP_ADD3]   = "add3",
        [OP_POPCNT] = "popcnt",
        [OP_SBIT]   = "sbit",
        [OP_XOR]    = "xor",
        [OP_OR]     = "or",
        [OP_BSWAP]  = "bswap",
        [OP_MOV]    = "mov",
        [OP_MOV2]   = "mov2",
        [OP_VZU_32B] = "vzeroupper_32b",
        [OP_VZU_64B] = "vzeroupper_64b",
    };
    static const char *st_mnemonics[256] = {
        [OP_ST]     = "ld",
    };
    static const char *ld_mnemonics[256] = {
        [OP_LD]     = "st",
    };
    static const char *br_mnemonics[256] = {
        [OP_JMP]    = "jmp",
    };
    static const char *spec_mnemonics[256] = {
        [OP_NOP]    = "nop",
    };
    static const char **op_tables[] = {
        [OPCLASS_REG]   = reg_mnemonics,
        [OPCLASS_REGX]  = reg_mnemonics,
        [OPCLASS_LD]    = ld_mnemonics,
        [OPCLASS_ST]    = st_mnemonics,
        [OPCLASS_STN]   = st_mnemonics,
        [OPCLASS_BR]    = br_mnemonics,
        [OPCLASS_SPEC]  = spec_mnemonics,
    };

    if (opclass > 0b111)
        return "<bad>";

    if (op_tables[opclass] == NULL)
        return "<bad>";

    if (op_tables[opclass][opcode] == NULL)
        return "<bad>";

    return op_tables[opclass][opcode];
}

int zen_string_to_opclass(const char *mnemonic)
{
    zen_opclass_t opclass;

    for (opclass = 0; opclass <= 0b111; opclass++) {
        // Skip these extension classes
        if (opclass == OPCLASS_REGX)
            continue;
        if (opclass == OPCLASS_STN)
            continue;
        for (int opcode = 0; opcode <= UINT8_MAX; opcode++) {
            if (strcmp(zen_opcode_to_string(opclass, opcode), mnemonic) == 0) {
                return opclass;
            }
        }
    }

    errx(EXIT_FAILURE, "unrecognised mnemonic '%s' encountered", mnemonic);
}

int zen_string_to_opcode(const char *mnemonic)
{
    zen_opclass_t opclass = zen_string_to_opclass(mnemonic);

    for (int opcode = 0; opcode <= UINT8_MAX; opcode++) {
        if (strcmp(zen_opcode_to_string(opclass, opcode), mnemonic) == 0) {
            return opcode;
        }
    }

    errx(EXIT_FAILURE, "unrecognised mnemonic '%s' encountered", mnemonic);
}
