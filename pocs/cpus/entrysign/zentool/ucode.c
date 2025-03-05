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
#include <errno.h>
#include <err.h>

#include "util.h"
#include "ucode.h"
#include "risc86.h"
#include "crypt.h"
#include "options.h"
#include "cpuid.h"
#include "factor.h"

static void __attribute__((constructor)) init_self_test()
{
    assert(sizeof(union BaseOp) == 8);
}

const char *dump_bits(uint64_t val, uint8_t size)
{
    static char bitbuf[128];

    memset(bitbuf, 0, sizeof bitbuf);

    for (int i = 0; i < size; i++) {
        bitbuf[size - i - 1] = (val & (1ULL << i)) ? '1' : '0';
    }

    return bitbuf;
}

void free_patch_file(patch_t *patch)
{
    free(patch->matchregs);
    free(patch->insns);
    free(patch);
}

patch_t * load_patch_file(const char *filename)
{
    FILE *infile;
    patch_t *patch;

    patch = calloc(1, sizeof *patch);

    if (patch == NULL) {
        err(EXIT_FAILURE, "memory allocation failure");
    }

    if ((infile = fopen(filename, "r")) == NULL) {
        err(EXIT_FAILURE, "failed to open specified file '%s'", filename);
    }

    // Check for a valid header
    if (fread(&patch->hdr, sizeof patch->hdr, 1, infile) != 1) {
        err(EXIT_FAILURE, "failed to read a supported microcode header from %s", filename);
    }

    switch (patch->hdr.format) {
        case 0x8004: patch->nmatch = 22;
                     patch->nquad  = 64;
                     break;
        case 0x8005: patch->nmatch = 38;
                     patch->nquad  = 128;
                     break;
        case 0x8015: patch->nmatch = 60;
                     patch->nquad  = 370;
                     break;
        case 0x8010: patch->nmatch = 60;
                     patch->nquad  = 370;
                     break;
        default:
            errx(EXIT_FAILURE, "Patch format %#x is not supported yet", patch->hdr.format);
    }

    patch->matchregs = calloc(patch->nmatch, sizeof(match_t));
    patch->insns = calloc(patch->nquad, sizeof(struct ucodeops));

    // Read match registers
    if (fread(patch->matchregs, sizeof(match_t), patch->nmatch, infile) != patch->nmatch)
        errx(EXIT_FAILURE, "failed to read match registers");

    if (fread(patch->insns, sizeof(struct ucodeops), patch->nquad, infile) != patch->nquad)
        err(EXIT_FAILURE, "input file may be truncated, insufficient instructions");

    // Now we have enough data to hash, so cache it in the structure.
    crypt_patch_hash(patch->hash, patch);

    if (options.debug) {
        dbgmsg("Computed Hash:");
        loghex(patch->hash, sizeof(patch->hash));
    }

    if (fgetc(infile) != EOF)
        logerr("there appears to be appended data, corrupt or unsupported format?");

    fclose(infile);

    return patch;
}

int save_patch_file(const patch_t *patch, const char *filename)
{
    FILE *outfile;

    if (options.outfile) {
        dbgmsg("ignoring filename %s and using outfile %s", filename, options.outfile);
        filename = options.outfile;
    }

    if (options.verbose) {
        fprintf(stderr, "saving patchfile to %s\n", filename);
    }

    if ((outfile = fopen(filename, "w")) == NULL) {
        err(EXIT_FAILURE, "failed to open specified file '%s'", filename);
    }

    if (fwrite(&patch->hdr, sizeof patch->hdr, 1, outfile) != 1) {
        err(EXIT_FAILURE, "failed to write a valid microcode header");
    }

    // Match registers
    if (fwrite(patch->matchregs, sizeof(match_t), patch->nmatch, outfile) != patch->nmatch) {
        err(EXIT_FAILURE, "failed to write match registers");
    }

    if (fwrite(patch->insns, sizeof(struct ucodeops), patch->nquad, outfile) != patch->nquad)
        err(EXIT_FAILURE, "output file may be truncated");

    fclose(outfile);
    return 0;
}
