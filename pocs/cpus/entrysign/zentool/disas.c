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

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <assert.h>
#include <stdlib.h>
#include <getopt.h>
#include <err.h>

#include "util.h"
#include "ucode.h"
#include "risc86.h"
#include "crypt.h"
#include "options.h"
#include "disas.h"
#include "compat.h"

static const int kMnemonicWidth = 8;

#define print_field(obj, name, fmt) do {                                            \
    print_struct_field(#name,                                                       \
                       fmt,                                                         \
                       bitsizeof(typeof(*(obj)), name),                             \
                       (8 * sizeof(*(obj))) - bitoffsetof(typeof(*(obj)), name),    \
                       (obj)->name);                                                \
} while (false)

#define REGISTER_BITFIELD(_type, _name) do {                                        \
    print_field(&op, _name, "%4X");                                                 \
} while (false)

int print_struct_field(const char *name, const char *format, int bits, int position, uint64_t value)
{
    logstr("\t; .%-9s: ", name);
    logstr(format, value);
    logstr("%*s\n", 1 + position, dump_bits(value, bits));
    return 0;
}

int dump_sequence_word(seqword_t seq)
{
    if (!options.verbose)
        return 0;

    if (seq.flags.action == SEQ_RELATIVE)
        logmsg("\t; Continue forward to relative quad %#0x", seq.target);
    if (seq.flags.action == SEQ_ABSOLUTE)
        logmsg("\t; Jump to ROM address %#0x", seq.target);
    if (seq.flags.nodelay)
        logmsg("\t; Continue sequence immediately");
    return 0;
}

static int dump_reg_op(struct RegOp op)
{
    char suffix[32] = {0};
    char mnemonic[64] = {0};
    char *sptr = &suffix[1];

    // This should generate a nice dump of the fields.
    if (options.verbose) {
        #include "RegOp_fields.h"
    }

    // The default size is 3, so no need to use a suffix.
    if (op.size != 3)
        *sptr++ = zen_size_to_suffix(op.size);

    // The set status flag is set.
    if (op.ss)
        *sptr++ = 's';

    if (op.class == OPCLASS_REGX)
        *sptr++ = 'x';

    // If we need a suffix, make sure the period is in there.
    if (suffix[1])
        suffix[0] = '.';

    snprintf(mnemonic, sizeof mnemonic, "%s%s",
                       zen_opcode_to_string(op.class, op.type),
                       suffix);

    // Now decode the remainder as necessary.
    putstr("\t%-*s\t%s, %s, ",
            kMnemonicWidth,
            mnemonic,
            zen_reg_to_string(op.reg2),
            zen_reg_to_string(op.reg1));

    if (op.mode3) {
        putstr("%#06x", op.imm16);
    } else {
        putstr("%s", zen_reg_to_string(op.reg0));
    }

    putmsg("");

    return 0;
}

static int dump_ldst_op(struct LdStOp op)
{
    char insn[128] = {0};
    char suffix[32] = {0};
    char mnemonic[64] = {0};
    char *sptr = &suffix[1];

    // This should generate a nice dump of the fields.
    if (options.verbose) {
        #include "LdStOp_fields.h"
    }

    // The default size is 3, so no need to use a suffix.
    if (op.size != 3)
        *sptr++ = zen_size_to_suffix(op.size);

    // Check if this is a storeop that doesn't touch memory.
    if (op.class == OPCLASS_STN) {
        op.class = OPCLASS_ST;
        *sptr++ = 'p';
    }

    // If we need a suffix, make sure the period is in there.
    if (suffix[1])
        suffix[0] = '.';

    // Now decode the remainder as necessary.
    snprintf(mnemonic, sizeof mnemonic, "%s%s",
                zen_opcode_to_string(op.class, op.type),
                suffix);

    snprintf(insn, sizeof insn, "%-*s\t", kMnemonicWidth, mnemonic);

    // register comes first
    if (op.ldst == true) {
        strlcat(insn, zen_reg_to_string(op.reg2), sizeof insn);
        strlcat(insn, ", ", sizeof insn);
    }

    if (op.segment != SEG_LS) {
        strlcat(insn, zen_segment_to_string(op.segment), sizeof insn);
        strlcat(insn, ":", sizeof insn);
    }

    strlcat(insn, "[", sizeof insn);
    strlcat(insn, zen_reg_to_string(op.reg1), sizeof insn);

    if (op.op3 == 0) {
        strlcat(insn, "+", sizeof insn);
        strlcat(insn, zen_reg_to_string(op.reg0), sizeof insn);
    }

    if (op.imm) {
        char displacement[16] = {0};

        snprintf(displacement, sizeof displacement, "%#0x", op.imm);
        strlcat(insn, "+", sizeof insn);
        strlcat(insn, displacement, sizeof insn);
    }

    strlcat(insn, "]", sizeof insn);

    if (op.ldst == false) {
        strlcat(insn, ", ", sizeof insn);
        strlcat(insn, zen_reg_to_string(op.reg2), sizeof insn);
    }

    putmsg("\t%s", insn);

    return 0;
}

static int dump_spec_op(struct SpecOp op)
{
    char insn[128] = {0};

    // This should generate a nice dump of the fields.
    if (options.verbose) {
        #include "SpecOp_fields.h"
    }

    // Now decode the remainder as necessary.
    snprintf(insn, sizeof insn, "%s.%c",
             zen_opcode_to_string(op.class, op.type),
             zen_size_to_suffix(op.size));

    putmsg("\t%-*s", kMnemonicWidth, insn);

    return 0;
}

static int dump_br_op(struct BrOp op)
{
    char insn[128] = {0};

    // This should generate a nice dump of the fields.
    if (options.verbose) {
        #include "BrOp_fields.h"
    }

    // Now decode the remainder as necessary.
    snprintf(insn, sizeof insn,
             "%s",
             zen_opcode_to_string(op.class, op.type));

    putmsg("\t%-*s\t%#x", kMnemonicWidth, insn, op.imm16);

    return 0;
}

int dump_op_disassembly(union BaseOp op)
{
    if (options.verbose) {
        logmsg("\t; %016lX %s", op.val, dump_bits(op.val, 64));
    }

    switch (op.class) {
        case OPCLASS_REGX:
        case OPCLASS_REG:   dump_reg_op(op.reg);
                            break;
        case OPCLASS_STN:
        case OPCLASS_ST:    dump_ldst_op(op.ld);
                            break;
        case OPCLASS_LD:    dump_ldst_op(op.ld);
                            break;
        case OPCLASS_SPEC:  dump_spec_op(op.spec);
                            break;
        case OPCLASS_BR:    dump_br_op(op.br);
                            break;
        default:
            putmsg("\t%-*s\t%#018lx ; Unhandled Class %d", kMnemonicWidth, ".dq", op.val, op.class);
    }
    return 0;
}

int dump_quad_disassembly(uopquad_t q)
{
    for (int i = 0; i < 4; i++) {
        dump_op_disassembly(q[i].op);
    }
    return 0;
}
