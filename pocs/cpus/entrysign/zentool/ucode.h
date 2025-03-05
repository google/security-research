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

#ifndef __UCODE_H
#define __UCODE_H

#pragma pack(push)
#pragma pack(1)

typedef union {
    uint32_t value;
    struct {
        unsigned m1         :13;
        unsigned _u1        :1;     // reg1 enabled?
        unsigned m2         :13;
        unsigned _u2        :1;     // reg2 enabled?
        unsigned _pad       :4;
    };
} match_t;

struct ucodehdr {
    uint32_t date;
    uint32_t revision;
    uint16_t format;
    uint8_t patchlen;   // datasz
    uint8_t init;       // flags
    uint32_t checksum;  // checksum
    uint16_t nbvid;
    uint16_t nbdid;
    uint16_t sbvid;
    uint16_t sbdid;
    union {
        uint32_t cpuid;
        struct {
            unsigned stepping:4;
            unsigned model:4;
            unsigned extmodel:4;
            unsigned extfam:4;
            uint16_t _pad;
        };
    };
    uint8_t biosrev;
    uint8_t flags;
    uint8_t reserved;
    uint8_t reserved2;
    uint8_t signature[256];
    uint8_t modulus[256];
    uint8_t check[256];
    struct {
        uint8_t autorun;
        uint8_t encrypted;
        uint8_t unknown1;
        uint8_t unknown2;
    } options;
    uint32_t rev;
};

enum {
    SEQ_RELATIVE = 0,
    SEQ_ABSOLUTE = 2,
};

typedef union seqword {
    uint32_t value;
    struct {
        unsigned target:13;
        unsigned _pad14:19;
    };
    struct {
        unsigned _pad0:16;
        unsigned action:4;
        unsigned nodelay:1;     // next quad is executed immediately
        unsigned _pad21:11;
    } flags;
} seqword_t;

struct SpecOp {
    unsigned imm16:16;
    unsigned isig:1;            // 1 = imm signed, 0 = imm unsigned
    unsigned _pad17:1;          // unknown
    unsigned _pad18:1;          // unknown
    unsigned mode3:1;           // 1 = 3rd op imm?
    unsigned _pad20:1;          // no obv effect
    unsigned reg0:5;            // dest
    unsigned reg1:5;            // r1
    unsigned reg2:5;            // dest
    unsigned rmod:1;            // 1=imm?
    unsigned _pad37:1;          // no obvious effect
    unsigned _pad38:1;          // no obvious effect
    unsigned _pad39:1;          // no obvious effect
    unsigned _pad40:1;          // crash
    unsigned _pad41:1;          // crash
    unsigned size:2;            // opsz = 8 << size
    unsigned sizemsb:1;
    unsigned _pada:2;
    unsigned type:8;
    unsigned _padc:4;       // operation?
    unsigned class:3;
    unsigned _pad63:2;
};

struct LdStOp {
    unsigned imm:10;            // displacement/immediate
    unsigned segment:4;
    unsigned unkn1:1;           // crashes
    unsigned nop3:1;            // no obvious effect
    unsigned unkn2:1;           // crashes
    unsigned mode:2;
    unsigned wordsz:1;          // 1=3rd op multiplied by word size, 0=bytes
    unsigned unknf:1;           // not sure
    unsigned reg0:5;            // src1
    unsigned reg1:5;            // src2
    unsigned reg2:5;            // dest
    // rmod=1,op3=1 reg2, [reg1+reg2+imm]
    // rmod=1,op3=0 reg2, [reg1+imm]
    unsigned rmod:1;            // 1 = deref?
    unsigned op3:1;             // 1 = 2, 0=3
    unsigned unkn6:4;
    unsigned size:2;            // src mem size?
    unsigned width:1;           // 1 = dest qword, 0 = dest dword
    unsigned ldst:1;            // 1 = ld, 2 = st
    unsigned unkn3:6;
    unsigned unknx:3;
    unsigned type:4;            // opcode?
    unsigned class:3;
    unsigned _pad63:2;          // no obvious effect
};

struct RegOp {
    unsigned imm16:16;
    unsigned isig:1;            // 1 = imm signed, 0 = imm unsigned
    unsigned _pad17:1;          // unknown
    unsigned _pad18:1;          // unknown
    unsigned mode3:1;           // 1 = 3rd op imm?
    unsigned _pad20:1;          // no obv effect
    unsigned reg0:5;            // dest
    unsigned reg1:5;            // r1
    unsigned reg2:5;            // dest
    unsigned rmod:1;            // 1=imm?
    unsigned cc:4;              // Condition Codes
    unsigned ss:1;              // "Set Status", 1=update flags
    unsigned size:2;            // opsz = 8 << size
    unsigned sizemsb:1;
    unsigned pada:2;            // unsure, could be part of ext
    unsigned type:8;            //
    unsigned ext:4;             //
    unsigned class:3;
    unsigned _pad63:2;          // seems unused, maybe compat with older class?

};

struct SRegOp {
    unsigned imm16:10;
    unsigned _pad:6;
    unsigned isig:1;            // 1 = imm signed, 0 = imm unsigned
    unsigned _pad17:1;          // unknown
    unsigned _pad18:1;          // unknown
    unsigned mode3:1;           // 1 = 3rd op imm?
    unsigned _pad20:1;          // no obv effect
    unsigned reg0:5;            // dest
    unsigned reg1:5;            // r1
    unsigned reg2:5;            // dest
    unsigned rmod:1;            // 1=imm?
    unsigned _pad37:1;          // no obvious effect
    unsigned _pad38:1;          // no obvious effect
    unsigned _pad39:1;          // no obvious effect
    unsigned _pad40:1;          // crash
    unsigned _pad41:1;          // crash
    unsigned size:2;            // opsz = 8 << size
    unsigned sizemsb:1;
    unsigned _pada:2;
    unsigned type:8;
    unsigned _padc:4;       // operation?
    unsigned class:3;
    unsigned _pad63:2;
};

struct BrOp {
    unsigned imm16:16;
    unsigned isig:1;            // 1 = imm signed, 0 = imm unsigned
    unsigned _pad17:1;          // unknown
    unsigned _pad18:1;          // unknown
    unsigned mode3:1;           // 1 = 3rd op imm?
    unsigned _pad20:1;          // no obv effect
    unsigned reg0:5;            // dest
    unsigned reg1:5;            // r1
    unsigned reg2:5;            // dest
    unsigned rmod:1;            // 1=imm?
    unsigned _pad37:1;          // no obvious effect
    unsigned _pad38:1;          // no obvious effect
    unsigned _pad39:1;          // no obvious effect
    unsigned _pad40:1;          // crash
    unsigned _pad41:1;          // crash
    unsigned size:2;            // opsz = 8 << size
    unsigned sizemsb:1;
    unsigned _pada:2;
    unsigned type:8;
    unsigned _padc:4;       // operation?
    unsigned class:3;
    unsigned _pad63:2;
};

union BaseOp {
    uint64_t val;
    struct BrOp br;
    struct RegOp reg;
    struct LdStOp ld;
    struct LdStOp st;
    struct SpecOp spec;
    struct SRegOp sreg;
    struct {
        uint64_t    _pad0 : 59;
        unsigned    class :  3;
        unsigned   _pad63 :  2;
    };
};

typedef union {
    union {
        uint64_t q;
        uint32_t d[2];
        uint16_t w[4];
        uint8_t  b[8];
    } value;
    union BaseOp op;
} uopquad_t[4];

struct ucodeops {
    uopquad_t   quad;
    seqword_t   seq;
};

typedef struct patch {
    struct ucodehdr hdr;
    match_t *matchregs;
    struct ucodeops *insns;
    uint8_t hash[16];
    unsigned exponent;
    unsigned nmatch;
    unsigned nquad;
} patch_t;

extern const struct ucodehdr kDefaultUcodeHdr;

const char *dump_bits_reversed(uint64_t val, uint8_t size);
const char *dump_bits(uint64_t val, uint8_t size);
void dump_regop(const struct RegOp *op);
void dump_ldstop(const struct LdStOp *op);
void dump_specop(const struct SpecOp *op);
void dump_brop(const struct BrOp *op);

void free_patch_file(patch_t *patch);
patch_t * load_patch_file(const char *filename);
int save_patch_file(const patch_t *patch, const char *filename);

extern const struct ucodeops kNop;
extern const uint64_t kNopInsn;

#pragma pack(pop)
#endif
