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
#include <err.h>

#include "util.h"
#include "ucode.h"
#include "risc86.h"
#include "crypt.h"
#include "options.h"
#include "factor.h"

static const struct option kLongOpts[] = {
    {          "help", false, NULL, 'h' },
    {  "patch-offset",  true, NULL, 'p' },
    {0},
};

static const char *kOptHelp[] = {
    "print this message",
    "choose where to patch header",
};

static int print_usage(const char *name)
{
    return print_usage_generic(name, "FILE", kLongOpts, kOptHelp);
}

int cmd_fixup_main(int argc, char **argv)
{
    patch_t *patch;
    ssize_t patchoffset;
    int longopt;
    int c;

    patchoffset = -1;

    reset_getopt();

    while ((c = getopt_long(argc, argv, "h", kLongOpts, &longopt)) != -1) {
        switch (c) {
            case 'h': print_usage(*argv);
                      return 0;
            case 'p': patchoffset = strtoul(optarg, NULL, 0);
                      break;
            case '?': print_usage(*argv);
                      errx(EXIT_FAILURE, "invalid options");
        }
    }

    if (optind != argc - 1) {
        print_usage(*argv);
        errx(EXIT_FAILURE, "must provide at least a filename");
    }

    patch = load_patch_file(argv[optind]);

    if (patchoffset == -1) {
        // Patch around the quad by default?
        patchoffset = sizeof(struct ucodehdr)
                        - offsetof(struct ucodehdr, options)
                        + sizeof(match_t) * patch->nmatch
                        + sizeof(*patch->insns) * patch->nquad;
        patchoffset -= sizeof(*patch->insns);
        patchoffset += 16 - (patchoffset % 16);
    }

    if (options.verbose) {
        logstr("signature before:");
        dump_patch_sig(patch);
    }

    fixup_patch_hash(patch, patchoffset);
    crypt_patch_hash(patch->hash, patch);

    if (options.verbose) {
        logstr("signature after:");
        dump_patch_sig(patch);
    }

    save_patch_file(patch, argv[optind]);
    free_patch_file(patch);

    return 0;
}
