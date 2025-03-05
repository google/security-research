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

#include <stdbool.h>
#include <time.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <getopt.h>
#include <search.h>
#include <err.h>

#include "util.h"
#include "ucode.h"
#include "risc86.h"
#include "crypt.h"
#include "options.h"
#include "cpuid.h"
#include "symbols.h"

#define MAX_FIELDS 64

typedef struct {
    const char *name;
    uint16_t    position;
    uint16_t    width;
    uint32_t    flags;
} bitfield_t;

#define REGISTER_BITFIELD(_type, _name) do {                    \
    tableptr->name      = #_name;                               \
    tableptr->position  = bitoffsetof(struct _type, _name);     \
    tableptr->width     = bitsizeof(struct _type, _name);       \
    tableptr++;                                                 \
} while(false);

static bitfield_t RegOp_fields[MAX_FIELDS];
static bitfield_t SRegOp_fields[MAX_FIELDS];
static bitfield_t LdStOp_fields[MAX_FIELDS];
static bitfield_t BrOp_fields[MAX_FIELDS];

static void __attribute__((constructor)) init_RegOp_fields(void)
{
    bitfield_t *tableptr = RegOp_fields;

    (void) tableptr;

    #include "RegOp_fields.h"
}

static void __attribute__((constructor)) init_LdStOp_fields(void)
{
    bitfield_t *tableptr = LdStOp_fields;

    (void) tableptr;

    #include "LdStOp_fields.h"
}

static void __attribute__((constructor)) init_BrOp_fields(void)
{
    bitfield_t *tableptr = BrOp_fields;

    (void) tableptr;

    #include "BrOp_fields.h"
}

static void __attribute__((constructor)) init_SRegOp_fields(void)
{
    bitfield_t *tableptr = SRegOp_fields;

    (void) tableptr;

    #include "SRegOp_fields.h"
}

static int field_compare_name(const void *a, const void *b)
{
    const char *x = a;
    const bitfield_t *y = b;
    return y->name ? strcmp(x, y->name) : -1;
}

bool set_field_name(union BaseOp *op, const char *fieldname, uint64_t value)
{
    bitfield_t *tableptr;
    bitfield_t *result;
    size_t numfields;
    uint64_t mask;

    dbgmsg("looking up field %s in %p", fieldname, op);

    // This field is always the same, so we don't need to look it up.
    if (strcmp(fieldname, "class") == 0) {
        op->class = value;
        return true;
    }

    switch (op->class) {
        case OPCLASS_SPEC:
        case OPCLASS_REG:   tableptr  = RegOp_fields;
                            numfields = ARRAY_SIZE(RegOp_fields);
                            break;
        case OPCLASS_STN:
        case OPCLASS_ST:    tableptr  = LdStOp_fields;
                            numfields = ARRAY_SIZE(LdStOp_fields);
                            break;
        case OPCLASS_LD:    tableptr  = LdStOp_fields;
                            numfields = ARRAY_SIZE(LdStOp_fields);
                            break;
        case OPCLASS_BR:    tableptr  = BrOp_fields;
                            numfields = ARRAY_SIZE(BrOp_fields);
                            break;
        default:
            // If we don't know the class, the only acceptable option is help.
            if (strcmp(fieldname, "help") == 0) {

                // I know the location of the class field in all objects.
                logmsg("Known fields for op class %u:", op->class);
                putmsg("\t%8s (width %2u, position %2u)",
                        "class",
                        bitsizeof(union BaseOp, class),
                        bitoffsetof(union BaseOp, class));
                return false;
            }

            // I don't know this class, so I don't know any fields to lookup.
            errx(EXIT_FAILURE, "cannot set field %s on unknown class %#x", fieldname, op->class);
            return false;
    }

    if (strcmp(fieldname, "help") == 0) {
        logmsg("Known fields for op class %u:", op->class);
        while (tableptr->name) {
            putmsg("\t%8s (width %2u, position %2u)", tableptr->name,
                                                      tableptr->width,
                                                      tableptr->position);
            tableptr++;
        }
        return false;
    }

    result = lfind(fieldname,
                   tableptr,
                   &numfields,
                   sizeof(bitfield_t),
                   field_compare_name);

    if (result == NULL) {
        errx(EXIT_FAILURE, "failed to find a field called %s, try field help for a list?", fieldname);
        return false;
    }

    dbgmsg("found field %s at position %u", fieldname, result->position);

    // Okay, so now make a mask so we remove all the bits.
    mask  = (1ULL << result->width) - 1;

    // Make sure this value fits while we have this value handy.
    if (value > mask) {
        errx(EXIT_FAILURE, "the specified value %#lx is too great for field %s", value, fieldname);
        return false;
    }

    // Now move the bits into position
    mask <<= result->position;

    // Now unset all the bits, because we're changing them.
    op->val &= ~mask;

    // Now set the new ones.
    op->val |= value << result->position;
    return true;
}
