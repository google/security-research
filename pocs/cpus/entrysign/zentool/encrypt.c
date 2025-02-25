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
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <assert.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <err.h>

#include "util.h"
#include "ucode.h"
#include "risc86.h"
#include "crypt.h"
#include "options.h"
#include "xxtea.h"

static uint32_t xxteaKey[4];

static int encrypt;
static int decrypt;

static const struct option kLongOpts[] = {
    {          "help", false, NULL, 'h' },
    {       "decrypt", false, &decrypt, true },
    {       "encrypt", false, &encrypt, true },
    {0},
};

static const char *kOptHelp[] = {
    "print this message",
    "decrypt an encypted patch",
    "encrypt an plaintext patch",
};

static int print_usage(const char *name)
{
    return print_usage_generic(name, "FILE", kLongOpts, kOptHelp);
}

int cmd_crypt_main(int argc, char **argv)
{
    patch_t *patch;
    size_t cryptsz;
    void *buf, *ptr;
    void *mptr;
    void *iptr;
    int longopt;
    int c;

    char *hexxteaKey = getenv("ZENTOOL_XXTEA_KEY");

    if (hexxteaKey == 0 ||
        sscanf(
            hexxteaKey,
            "%8x%8x%8x%8x",
            &xxteaKey[0], &xxteaKey[1], &xxteaKey[2], &xxteaKey[3]
        ) != 4) {
      errx(EXIT_FAILURE, "missing ZENTOOL_XXTEA_KEY environment variable");
    }

    reset_getopt();

    if (strcmp(*argv, "encrypt") == 0)
        encrypt = true;
    if (strcmp(*argv, "decrypt") == 0)
        decrypt = true;

    while ((c = getopt_long(argc, argv, "h", kLongOpts, &longopt)) != -1) {
        switch (c) {
            case 'h': print_usage(*argv);
                      return 0;
            case '?': print_usage(*argv);
                      errx(EXIT_FAILURE, "invalid options");
        }
    }

    if (optind >= argc) {
        print_usage(*argv);
        errx(EXIT_FAILURE, "must provide a filename");
    }

    if ((encrypt ^ decrypt) != true) {
        errx(EXIT_FAILURE, "must specify encryption or decryption");
    }

    patch = load_patch_file(argv[optind]);

    // Calculate size of encrypted data
    cryptsz = sizeof(match_t) * patch->nmatch
            + sizeof(*patch->insns) * patch->nquad;

    // Allocate a temporary working buffer.
    mptr = ptr = buf = malloc(cryptsz);

    if (buf == NULL) {
        errx(EXIT_FAILURE, "memory allocation failure");
    }

    // Copy over the data.
    iptr = ptr = mempcpy(ptr, patch->matchregs, sizeof(match_t) * patch->nmatch);
    mempcpy(ptr, patch->insns, sizeof(*patch->insns) * patch->nquad);

    if (encrypt && patch->hdr.options.encrypted == false) {
        xxtea_encrypt(buf, cryptsz, xxteaKey);
        patch->hdr.options.encrypted = true;
    }

    if (decrypt && patch->hdr.options.encrypted == true) {
        xxtea_decrypt(buf, cryptsz, xxteaKey);
        patch->hdr.options.encrypted = false;
    }

    // Encryption operations complete, now restore them
    memcpy(patch->matchregs, mptr, sizeof(match_t) * patch->nmatch);
    mempcpy(patch->insns, iptr, sizeof(*patch->insns) * patch->nquad);

    // All options applied, now save the output
    save_patch_file(patch, argv[optind]);
    free_patch_file(patch);
    free(buf);
    return 0;
}
