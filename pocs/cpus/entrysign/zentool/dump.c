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
#include <time.h>
#include <err.h>
#include <errno.h>

#include "util.h"
#include "ucode.h"
#include "risc86.h"
#include "crypt.h"
#include "options.h"
#include "data.h"
#include "disas.h"
#include "cpuid.h"
#include "factor.h"

static int printmatches;
static int disassemble;
static int printhdr;

const uint64_t kNopInsn = 0x007f9c0000000000;

const struct ucodeops kNop = {
    .quad[0] = { .value.q = kNopInsn },
    .quad[1] = { .value.q = kNopInsn },
    .quad[2] = { .value.q = kNopInsn },
    .quad[3] = { .value.q = kNopInsn },
    .seq     = { .value = 0x04000001 },
};

static const struct option kLongOpts[] = {
    {          "help", false, NULL, 'h' },
    {           "all", false, NULL, false },
    {    "match-regs", false, &printmatches, true },
    {   "disassemble", false, &disassemble, true },
    {0},
};

static const char *kOptHelp[] = {
    "(-h) print this message",
    "(-a) print everything",
    "(-m) show all match registers",
    "(-d) disassemble microops",
};

static int print_usage(const char *name)
{
    return print_usage_generic(name, "FILE", kLongOpts, kOptHelp);
}

static void dump_ucode_hdr(const patch_t *patch)
{
    char datestr[64] = {0};
    uint8_t signedhash[16] = {0};
    uint8_t actualhash[16] = {0};
    struct tm date = {0};
    bool verified = false;
    const struct ucodehdr *hdr = &patch->hdr;

    uint8_t *check= alloca(sizeof hdr->check);

    snprintf(datestr, 64, "%08X", hdr->date);
    strptime(datestr, "%02m%02d%Y", &date);
    strftime(datestr, 64, "%a %b %e %Y", &date);

    putmsg("Date:        %08x (%s)", hdr->date, datestr);
    putmsg("Revision:    %08x", hdr->revision);
    putmsg("Format:      %04x", hdr->format);
    logmsg("Patchlen:    %02x", hdr->patchlen);
    logmsg("Init:        %02x", hdr->init);
    logmsg("Checksum:    %08x", hdr->checksum);
    logmsg("NorthBridge: %04x:%04x", hdr->nbvid, hdr->nbdid);
    logmsg("SouthBridge: %04x:%04x", hdr->sbvid, hdr->sbdid);
    putmsg("Cpuid:       %08x %s", hdr->cpuid,
        zen_cpuid_lookup(hdr->extfam,
                         hdr->model,
                         hdr->extmodel,
                         hdr->stepping));
    logmsg("  Stepping   %u", hdr->stepping);
    logmsg("  Model:     %u", hdr->model);
    logmsg("  Extmodel:  %u", hdr->extmodel);
    logmsg("  Extfam:    %u", hdr->extfam);
    logmsg("BiosRev:     %02x", hdr->biosrev);
    logmsg("Flags:       %02x", hdr->flags);
    logmsg("Reserved:    %04x", hdr->reserved);

    crypt_signed_hash(signedhash, hdr->modulus, hdr->signature, sizeof hdr->modulus);
    crypt_patch_hash(actualhash, patch);

    if (memcmp(signedhash, actualhash, sizeof signedhash) == 0)
        verified = true;

    putmsg("Signature:   %02x... (use --verbose to see) (%s)",
        hdr->signature[0],
        verified ? "GOOD" : "BAD");

    if (options.verbose)
        loghex(hdr->signature, sizeof hdr->signature);

    if (options.verbose) {
        logmsg("SignedHash:");
        loghex(signedhash, 16);
        logmsg("ActualHash:");
        loghex(actualhash, 16);
    }

    putmsg("Modulus:     %02x... (use --verbose to see)", hdr->modulus[0]);

    if (options.verbose)
        loghex(hdr->modulus, sizeof hdr->modulus);

    if (options.verbose) {
        uint8_t hash[16] = {0};
        crypt_calc_modhash(hash, hdr->modulus, sizeof hdr->modulus);
        logmsg("ModHash:");
        loghex(hash, 16);
    }

    // Make sure the check field is valid
    crypt_calc_check(check, hdr->modulus, sizeof hdr->modulus);

    if (memcmp(check, hdr->check, sizeof hdr->check) == 0)
        verified = true;

    putmsg("Check:       %02x... (use --verbose to see) (%s)",
        hdr->check[0],
        verified ? "GOOD" : "BAD");

    if (options.verbose)
        loghex(hdr->check, sizeof hdr->check);

    if (verified == false) {
        logerr("The check field is BAD, i.e. does not match modulus");
        if (options.verbose) {
            logmsg("Expected:");
            loghex(check, sizeof hdr->check);
        }
    }

    putmsg("Autorun:     %s", hdr->options.autorun   ? "true" : "false");
    putmsg("Encrypted:   %s", hdr->options.encrypted ? "true" : "false");

    if (hdr->options.encrypted)
        logmsg("    Use `%s decrypt` to decrypt update", program_invocation_short_name);

    putmsg("Revision:    %08x (Signed)", hdr->rev);

    return;
}

int cmd_dump_main(int argc, char **argv)
{
    patch_t *patch;
    int longopt;
    int c;

    reset_getopt();

    while ((c = getopt_long(argc, argv, "hdma", kLongOpts, &longopt)) != -1) {
        switch (c) {
            case 'h': print_usage(*argv);
                      return 0;
            case 'd': disassemble = true;
                      break;
            case 'm': printmatches = true;
                      break;
            case '?': print_usage(*argv);
                      errx(EXIT_FAILURE, "invalid options specified");
            case  0 : if (strcmp(kLongOpts[longopt].name, "all") == 0) {
            case 'a':   printmatches = true;
                        disassemble  = true;
                        printhdr     = true;
                      }
                      break;
        }
    }

    // If no other options specified, just print header
    if (!printmatches && !disassemble)
        printhdr = true;

    // No input file specified
    if (argc == optind) {
        print_usage(*argv);
        errx(EXIT_FAILURE, "must provide at least an input file");
    }

    patch = load_patch_file(argv[optind]);

    if (printhdr) {
        dump_ucode_hdr(patch);
    }

    if (printmatches || disassemble) {
        if (patch->hdr.options.encrypted) {
            errx(EXIT_FAILURE, "This patch is encrypted, decryption recommended first");
        }
    }

    if (printmatches) {
        logmsg("; Patch %#x Match Registers (%u total)", patch->hdr.revision, patch->nmatch * 2);

        if (!options.verbose) {
            logmsg("; (use --verbose to see empty slots)");
        }

        for (size_t i = 0; i < patch->nmatch; i++) {
            char *name1 = NULL;
            char *name2 = NULL;

            // See if I know a symbolic name for these MR.
            if (patch->hdr.options.encrypted == false) {
                name1 = data_lookup_name(patch, TYPE_MATCH, patch->matchregs[i].m1);
                name2 = data_lookup_name(patch, TYPE_MATCH, patch->matchregs[i].m2);
            }

            if (patch->matchregs[i].m1 != 0 || options.verbose) {
                putmsg("\t[%-2lu] %04X%s%s", i * 2, patch->matchregs[i].m1,
                    name1 ? " @"  : "",
                    name1 ? name1 : ""
                );
            }

            if (patch->matchregs[i].m2 != 0 || options.verbose) {
                putmsg("\t[%-2lu] %04X%s%s", i * 2 + 1, patch->matchregs[i].m2,
                    name2 ? " @"  : "",
                    name2 ? name2 : ""
                );
            }

            // These could be NULL, but that doesn't matter.
            free(name1);
            free(name2);
        }
    }

    if (disassemble) {
        logmsg("; Patch %#0x OpQuad Disassembly (%u total)", patch->hdr.revision, patch->nquad);

        if (!options.verbose) {
            logmsg("; (use --verbose to see further details)");
        }

        for (size_t i = 0; i < patch->nquad; i++) {
            uint16_t quad_address = 0x2000 - (patch->nquad - i);
            // A more compact representation for nops.
            if (memcmp(&patch->insns[i], &kNop, sizeof kNop) == 0) {
                logmsg(".quad %-14u\t; @%#04x Empty OpQuad (nop) ", i, quad_address);
                continue;
            }

            putmsg(".quad %2u, %#010x\t; @%#04x", i, patch->insns[i].seq.value, quad_address);
            dump_sequence_word(patch->insns[i].seq);
            dump_quad_disassembly(patch->insns[i].quad);
        }
    }

    free_patch_file(patch);
    return 0;
}
