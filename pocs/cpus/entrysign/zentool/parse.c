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
#include "parse.h"
#include "options.h"

// segment:[base+index+0xdisp]
static bool zen_parse_ldst_memop(const char *str, struct LdStOp *op)
{
    char *memop     = strdupa(str);
    char *segment   = strdupa("ls");
    char base[8]    = {0};
    char index[8]   = {0};
    char disp[8]    = {0};
    uint64_t displacement = 0;

    dbgmsg("attempting to parse %s as a memop", str);

    // Check for segment override.
    if (strchr(memop, ':')) {
        // The user did specify a segment, so extract it.
        segment = memop;

        // Move memop past the ':', then detach the segment.
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wanalyzer-null-dereference"
        memop       = strchr(memop, ':');
        *memop++    = '\0';
        #pragma GCC diagnostic pop

        dbgmsg("found a segment override prefix: %s, remaining is now %s", segment, memop);
    }

    if (sscanf(memop, "[%[a-z0-9]+%[a-z0-9]+%[0-9]]", base, index, disp) < 1) {
        dbgmsg("i dont think %s is a memop", memop);
        // This is probably not a memop.
        return false;
    }

    op->segment = zen_string_to_segment(segment);
    op->reg1    = zen_string_to_reg(base);
    op->op3     = true;

    // If a displacement was specified, then index must be present.
    // [base+index+disp]
    if (*disp) {
        if (opt_num_parse_max(disp, &displacement, 1 << 9) == false) {
            errx(EXIT_FAILURE, "the displacement %s was not valid", disp);
        }
        op->reg0 = zen_string_to_reg(index);
        op->op3  = false;
    } else if (*index) {
        // It's possible index was a displacement
        // [base+disp]
        if (opt_num_parse_max(index, &displacement, 1 << 9) == false) {
            // It's not a number, it must be a register?
            op->reg0 = zen_string_to_reg(index);
            op->op3  = false;
        }
    } else {
        // No index or displacement
        // [base]
    }

    op->imm = displacement;
    return true;
}


// Set the size field in a BaseOp, the size is in bits and is 8 << size.
static bool zen_opcode_suffix(const char *suffixes, union BaseOp *op)
{
    int size   = 3;
    int status = 0;
    int ruxex  = 0;
    int pure   = 0;

    if (suffixes == NULL || *suffixes == '\0') {
        goto finished;
    }

    for (const char *s = suffixes; *s; s++) {
        switch (*s) {
            // Size flags
            case 'q': size = 3; break;
            case 'd': size = 2; break;
            case 'w': size = 1; break;
            case 'b': size = 0; break;
            // Set Status
            case 's': status = 1; break;
            // Choose RUX
            case 'x': ruxex = 1; break;
            // Store that cannot fault.
            case 'p': pure = 1; break;
            default:
                errx(EXIT_FAILURE, "unrecognized opcode suffix %c in %s", *s, suffixes);
        }
    }

finished:

    switch (op->class) {
        case OPCLASS_REG:
        case OPCLASS_REGX:
            op->reg.size    = size;
            op->reg.sizemsb = op->reg.size >> (bitsizeof(union BaseOp, reg.size) - 1);

            // Currently you can set all flags or no flags
            if (status) {
                op->reg.ss = status;
                op->reg.cc = ~0;
            }

            // Register Unit X Exclusively
            if (ruxex) {
                op->class = OPCLASS_REGX;
            }

            break;
        case OPCLASS_LD:
        case OPCLASS_ST:
        case OPCLASS_STN:
            op->ld.size = size;
            switch (size) {
                case 3: op->ld.width = true;
                        break;
                case 2: op->ld.width = false;
                        break;
                default:
                    errx(EXIT_FAILURE, "unsupported size %u for ldst", size);
            }
            if (pure) {
                if (op->class != OPCLASS_ST) {
                    errx(EXIT_FAILURE, "pure suffix used with non-store?");
                }
                op->class = OPCLASS_STN;
            }
            break;
        case OPCLASS_SPEC:
            op->spec.size = size;
            op->spec.sizemsb = op->reg.size >> (bitsizeof(union BaseOp, reg.size) - 1);
            break;
        case OPCLASS_BR:
            break;
        default:
            errx(EXIT_FAILURE, "unknown opclass %#x", op->class);
    }

    return true;
}

bool zen_assemble_line(const char *line, union BaseOp *op)
{
    char opcode[128] = {0};
    char op1[128]    = {0};
    char op2[128]    = {0};
    char op3[128]    = {0};

    memset(op, 0, sizeof *op);

    op->class = OPCLASS_REG;

    // Parse out the opcode and the operands.
    if (sscanf(line, "%127s %127[^, \t\n], %127[^, \t\n], %127[^ \t\n]", opcode, op1, op2, op3) >= 1) {
        char *end;
        char *suffix = strchrnul(opcode, '.');
        uint16_t imm;
        uint16_t type;

        // This is a pseudo-op, e.g. .dq, .quad, etc)
        if (*opcode && suffix == opcode) {
            if (strcmp(opcode, ".dq") == 0) {
                op->val = strtoull(op1, NULL, 0);
                return true;
            }
            // Ignore for now.
            return false;
        }

        // Remove any suffix so we can look up the opcode.
        if (*suffix != '\0') *suffix++ = '\0';

        // Convert mnemonic to opcode.
        type = zen_string_to_opcode(opcode);

        // Lookup what class that opcode is from
        op->class = zen_string_to_opclass(opcode);

        // Two options, op3 is an immediate/displacement or a register.
        imm = strtoul(op3, &end, 0);

        switch (op->class) {
            case OPCLASS_REG:
            case OPCLASS_REGX:
                op->reg.type  = type;

                // Now parse operands
                op->reg.reg2 = zen_string_to_reg(op1);
                op->reg.reg1 = zen_string_to_reg(op2);

                // Check if that could be parsed.
                if (*op3 && *end == '\0') {
                    op->reg.imm16 = imm;
                    op->reg.mode3 = true;
                    op->reg.rmod = true;
                } else if (*op3) {
                    // Not an immediate, maybe a register.
                    op->reg.reg0 = zen_string_to_reg(op3);
                    op->reg.rmod = true;
                } else {
                    // I think this is correct for single operand insns?
                    op->reg.reg0 = op->reg.reg1;
                    op->reg.rmod = true;
                }
                break;
            // Example: ld.q rax, ms:[rsi+rdi+0x123]
            // Example: ld.q ms:[rsi+rdi+0x123], rax
            case OPCLASS_ST:
            case OPCLASS_STN:
            case OPCLASS_LD: {
                op->ld.type = type;

                // See if this is a store operation.
                if (zen_parse_ldst_memop(op1, &op->ld) == true) {
                    // it is, so the other operation must be a reg
                    op->ld.reg2     = zen_string_to_reg(op2);
                    op->ld.ldst     = false;
                    op->ld.unknx    = 4;
                    op->ld.unkn3    = 0x2F;
                } else if (zen_parse_ldst_memop(op2, &op->ld) == true) {
                    // this must be a load
                    op->ld.reg2     = zen_string_to_reg(op1);
                    op->ld.ldst     = true;
                    op->ld.unknx    = 6;
                    op->ld.unkn3    = 0b111100;
                } else {
                    errx(EXIT_FAILURE, "unable to find a valid memory reference in %s", line);
                }

                op->ld.rmod     = true;
                op->ld.nop3     = 1;
                break;
            }

            // Example: jmp 0x123
            case OPCLASS_BR: {
                op->br.type = type;

                // Is op1 just an immediate?
                imm = strtoul(op1, &end, 0);

                if (*op1 && *end == '\0') {
                    op->br.imm16 = imm;
                    op->br.rmod  = true;
                }

                break;
            }
            case OPCLASS_SPEC: {
                op->spec.type = type;
                break;
            }

            default:
                errx(EXIT_FAILURE, "sorry, dont handle this class yet");
        }

        // If there was an opcode suffix, parse it.
        zen_opcode_suffix(suffix, op);

        return true;
    }
    return false;
}
