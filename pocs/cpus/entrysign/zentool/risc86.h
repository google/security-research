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

#ifndef __RISC86_H
#define __RISC86_H

typedef enum {
    SEG_VS      = 0b0000,
    SEG_LS      = 0b0110,
    SEG_MS      = 0b0101,
    SEG_PS      = 0b1001,
} zen_seg_t;

typedef enum {
    OP_NSUB     = 0b00011001,
    OP_AND      = 0b00110000,
    OP_SHL      = 0b01000000,
    OP_BLL      = 0b01000001,
    OP_ROL      = 0b01000010,
    OP_RLC      = 0b01000100,
    OP_RRD      = 0b01000110,
    OP_SRC      = 0b01000111,
    OP_SHR      = 0b01001000,
    OP_ROR      = 0b01001010,
    OP_RRC      = 0b01001100,
    OP_SRD      = 0b01001111,
    OP_SUB      = 0b01010000,
    OP_SBB      = 0b01010010,
    OP_NADD     = 0b01010101,
    OP_ADC      = 0b01011101,
    OP_ADD      = 0b01011111,
    OP_ADD2     = 0b01011100,
    OP_ADD3     = 0b01011110,
    OP_POPCNT   = 0b01110000,
    OP_SBIT     = 0b01110010,
    OP_XOR      = 0b10110101,
    OP_OR       = 0b10111110,
    OP_BSWAP    = 0b10101001,
    OP_MOV      = 0b10100000,
    OP_MOV2     = 0b10010011,
    OP_VZU_32B   = 0x7f,
    OP_VZU_64B     = 0x6f,
} zen_reg_opcode_t;

typedef enum {
    OP_LD     = 0x00,
} zen_ld_opcode_t;

typedef enum {
    OP_ST     = 0x00,
} zen_st_opcode_t;

typedef enum {
    OP_NOP    = 0xFF,
} zen_spec_opcode_t;

typedef enum {
    OP_JMP    = 0x05,
} zen_br_opcode_t;

typedef enum {
    OP_SREG   = 0xA0,
} zen_sreg_opcode_t;

// This is table 3.4 (pg 199) from AOHPM, the values appear to still be valid
// in Zen.
typedef enum {
    OPCLASS_SPEC    = 0b000, // a SpecOp -- not issued to an execution unit
    OPCLASS_LD      = 0b010, // a LdOp -- issued to the Load Unit
    OPCLASS_STN     = 0b100, // a StOp -- issued to the Store Unit, but does not reference memory
    OPCLASS_ST      = 0b101, // a StOp -- may or may not reference memory, could fault
    OPCLASS_REGX    = 0b110, // a RegOp -- issued to RUX (the more capable Register Unit)
    OPCLASS_REG     = 0b111, // a RegOp -- may be issued to RUX or RUY
    OPCLASS_BR      = 0b001, // Maybe? This is not in the book
} zen_opclass_t;

typedef enum {
    REG_RAX    = 16,
    REG_RCX    = 17,
    REG_RDX    = 18,
    REG_RBX    = 19,
    REG_RSP    = 20,
    REG_RBP    = 21,
    REG_RSI    = 22,  // also R3?
    REG_RDI    = 23,
    REG_R8     = 24,
    REG_R9     = 25,
    REG_R10    = 26,
    REG_R11    = 27,
    REG_R12    = 28,
    REG_R13    = 29,
    REG_R14    = 30,
    REG_R15    = 31,
    REG_LAST   = 0b11111 + 1,
} zen_reg_t;

int zen_string_to_opcode(const char *mnemonic);
int zen_string_to_opclass(const char *mnemonic);
int zen_string_to_reg(const char *name);
int zen_string_to_segment(const char *segment);
char zen_size_to_suffix(uint8_t size);
const char *zen_opcode_to_string(zen_opclass_t opclass, uint8_t opcode);
const char *zen_reg_to_string(zen_reg_t reg);
const char *zen_segment_to_string(zen_seg_t segment);

#endif
