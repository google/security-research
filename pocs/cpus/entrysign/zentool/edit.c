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
#include <errno.h>
#include <time.h>
#include <err.h>
#include <unistd.h>

#include "util.h"
#include "ucode.h"
#include "risc86.h"
#include "crypt.h"
#include "options.h"
#include "data.h"
#include "parse.h"
#include "fields.h"

static const struct option kLongOpts[] = {
    {          "help", false, NULL, 'h' },
    {      "hdr-date",  true, NULL, false },
    {  "hdr-revision",  true, NULL, false },
    {    "hdr-revlow",  true, NULL, false },
    {    "hdr-revinc", false, NULL, false },
    {   "hdr-autorun",  true, NULL, false },
    {     "hdr-cpuid",  true, NULL, false },
    {         "match",  true, NULL, false },
    {           "nop",  true, NULL, false },
    {           "seq",  true, NULL, false },
    {          "insn",  true, NULL, false },
    {    "insn-field",  true, NULL, false },
    {      "fastpath",  true, NULL, false },
    {0},
};

static const char *kOptHelp[] = {
    "print this message",
    "set date to DDMMYYYY",
    "set revision to N",
    "set low-order revision octet to N",
    "increment revision",
    "set the run-on-load flag to specified flag, true or false",
    "set the cpuid to N",
    "set match register X=Y, e.g. all=0 or 1,2,3=@rdtsc",
    "set instruction X to nop, use 'all' for all instructions",
    "set sequence word X=Y, X can be a number, range like 0-6,3,4 or all",
    "set instruction X=Y, e.g. 2-4=0x123 or 5='add rax, rax, 1'",
    "set instruction X.field=Y, e.g. all.type=0x12, try all.help for a field list.",
};

static int print_usage(void)
{
    logmsg("modify fields in a microcode update");
    print_usage_generic("edit", "FILE", kLongOpts, kOptHelp);
    logmsg("");
    logmsg("use the global `--output` flag to change destination");
    logmsg("e.g. %s --output foo.bin edit --bar input.bin", program_invocation_short_name);
    return 0;
}

static int set_insn_value(patch_t *patch, char const *options)
{
    char *range = strdupa(options);
    char *value = strchr(range, '=');
    union BaseOp op = {0};
    uint64_t num;

    // Verify we got a range and a value.
    if (value == NULL) {
        errx(EXIT_FAILURE, "you didnt specify a quad number for insn, e.g. 6=0x1234");
    }

    // Remove the equals, so now range and value are both nul terminated.
    *value++ = '\0';

    // Check if a number was specified
    if (opt_num_parse(value, &num) == true)
        goto setrange;

    // Not a number, check if it's a valid assembly instruction
    if (zen_assemble_line(value, &op) == true) {
        // Okay, seems good, convert that back into a number.
        num = op.val;

        // Now treat it like a number.
        goto setrange;
    }

    errx(EXIT_FAILURE, "failed to parse the value specified, %s", value);

  setrange:
    // Seems okay, check which instructions user is setting.
    for (size_t i = 0; i < patch->nquad * 4; i++) {
        if (opt_num_inrange(range, i)) {
            dbgmsg("setting instruction %u to %08lx", i, num);
            patch->insns[i / 4].quad[i % 4].value.q = num;
        }
    }
    return 0;
}

// usage:
//           --seq 0,1,2,3-5=0x12345
//           --seq 0=1
//           --seq all=0xffffff
//
static int set_sequence_word(patch_t *patch, char const *options)
{
    char *range = strdupa(options);
    char *value = strchr(range, '=');
    uint64_t seqval;

    // Verify we got a range and a value.
    if (value == NULL) {
        errx(EXIT_FAILURE, "you didnt specify a quad number for seq, e.g. 6=0x1234");
    }

    // Remove the equals, so now range and value are both nul terminated.
    *value++ = '\0';

    // Extract the sequence number.
    if (opt_num_parse_max(value, &seqval, UINT32_MAX) == false) {
        errx(EXIT_FAILURE, "failed to parse the number %s", value);
    }

    // Seems okay, check which instructions user is setting.
    for (size_t i = 0; i < patch->nquad; i++) {
        if (opt_num_inrange(range, i)) {
            dbgmsg("setting sequence word for quad %u to %08x", i, seqval);
            patch->insns[i].seq.value = seqval;
        }
    }
    return 0;
}

static int set_fastpath_hook(patch_t *patch, char const *options)
{
/*
./zentool --output=modified.bin edit --nop all --match all=0 --seq all=7 --insn q40i0="xor rax, rax, rax" --insn q40i1="add rax, rax, 0x1337" --fastpath 0xbb000000,0xff000000,0x00000005 --hdr-revlow 0x6 template.bin && ./zentool resign modified.bin && sudo ./zentool load --cpu=2 modified.bin && taskset -c 2 ./opcodes
*/
    // --fastpath=0x1234,0x1234,0x1234
    char **values = str_split(options, ',');
    srand(time(NULL) ^ getpid());
    // 77 vzeroupper
    // BB BTC
    if (strcmp(values[0], "rand") == 0) {
        patch->matchregs[10].value = rand();
    } else {
        patch->matchregs[10].value = strtoul(values[0], NULL, 16); //rand();
    }
    if (strcmp(values[1], "rand") == 0) {
        patch->matchregs[14].value = rand();
    } else {
        patch->matchregs[14].value = strtoul(values[1], NULL, 16);  // c0=>00, break many insns
    }
    if (strcmp(values[2], "rand") == 0) {
        patch->matchregs[18].value = rand();
    } else {
        patch->matchregs[18].value = strtoul(values[2], NULL, 16); //rand() & 0xffffffff; // 0x00000005;
    }
    // [18] 0x00000001; => crash on 0xbb match
    // 0x2e858121 crash
    // 0x61527801 crash (byte0 = 1)
    printf("fastpath[10]=0x%08x [14]=0x%08x [18]=0x%08x\n",
        patch->matchregs[10].value,
        patch->matchregs[14].value,
        patch->matchregs[18].value);
    return 0;
}

// usage:
//           --insn-field 0,1,2,3-5.foo=0x12345
//           --insn-field 0.bar=1
//           --insn-field all.baz=0xffffff
//
static int set_insn_field(patch_t *patch, char const *options)
{
    char *range = strdupa(options);
    char *value = strchr(range, '=');
    char *field = strchr(range, '.');
    uint64_t num;

    // Verify we got a range and a value.
    if (value == NULL || field == NULL) {
        errx(EXIT_FAILURE, "you didnt specify a range and field, e.g. 6.type=0x1234");
    }

    // Remove the ./=, so now range, value and field are all nul terminated.
    *value++ = '\0';
    *field++ = '\0';

    // Extract the number.
    if (opt_num_parse(value, &num) == false) {
        errx(EXIT_FAILURE, "failed to parse the number %s", value);
    }

    // Seems okay, check which instructions user is setting.
    for (size_t i = 0; i < patch->nquad * 4; i++) {
        if (opt_num_inrange(range, i)) {
            if (set_field_name(&patch->insns[i / 4].quad[i % 4].op,
                               field,
                               num) == false) {
                errx(EXIT_FAILURE, "unable to set the specified field");
            }
        }
    }
    return 0;
}

// Examples:
//  all
//  0-3,4-
//  q1
//  q0i3
//
static int set_insn_nop(patch_t *patch, const char *range)
{
    for (size_t q = 0; q < patch->nquad; q++) {
        bool nop_entire_quad = true;

        // Check each instruction of this quad to see if its in range
        for (size_t i = 0; i < 4; i++) {
            if (opt_num_inrange(range, q * 4 + i)) {
                dbgmsg("instruction %u will be nopped", q * 4 + i);
                patch->insns[q].quad[i].value.q = kNopInsn;
            } else {
                nop_entire_quad = false;
            }
        }

        // If the whole thing was nopped, we should reset the sequence word.
        if (nop_entire_quad) {
            dbgmsg("quad %u was nopped, resetting sequence word", q);
            memcpy(&patch->insns[q], &kNop, sizeof kNop);
        }
    }
    return 0;
}

// Examples:
//      0=0x1234
//      all=0
//      33-24=@rdtscp
static int set_match_registers(patch_t *patch, const char *options)
{
    char *range = strdupa(options);
    char *value = strchr(range, '=');
    uint64_t num;

    if (value == NULL) {
        errx(EXIT_FAILURE, "the match spec %s was invalid, no value", options);
    }

    // Remove the equal, now reg=num and val=num
    *value++ = '\0';

    // Extract the number.
    if (*value == '@') {
        // It's a symbolic number, look that up
        num = data_lookup_symbol(patch, TYPE_MATCH, ++value);
    } else {
        if (opt_num_parse_max(value, &num, 1 << 13) == false) {
            errx(EXIT_FAILURE, "the number %s was not a valid match register", value);
        }
    }

    // Seems okay
    for (size_t i = 0; i < patch->nmatch * 2; i++) {
        if (opt_num_inrange(range, i) == false)
            continue;

        dbgmsg("setting match register %zu to %lu", i, num);

        // We are changing this, check which field to set.
        if (i % 2) {
            patch->matchregs[i / 2]._u2 = !!num;
            patch->matchregs[i / 2].m2  = num;
        } else {
            patch->matchregs[i / 2]._u1 = !!num;
            patch->matchregs[i / 2].m1 = num;
        }
    }
    return 0;
}

int cmd_edit_main(int argc, char **argv)
{
    patch_t *patch;
    int longopt;
    int c;

    reset_getopt();

    // Parse the first few generic options.
    while ((c = getopt_long(argc, argv, "h", kLongOpts, &longopt)) != -1) {
        switch (c) {
            case 'h': print_usage();
                      return 0;
            case '?': print_usage();
                      errx(EXIT_FAILURE, "invalid options");
        }
    }

    // No input file specified
    if (argc == optind) {
        print_usage();
        errx(EXIT_FAILURE, "must provide at least an input file");
    }

    patch = load_patch_file(argv[optind]);

    reset_getopt();

    // Okay, now parse the rest of the options
    while ((c = getopt_long(argc, argv, "", kLongOpts, &longopt)) != -1) {
        const char *opt;

        if (c != 0) {
            print_usage();
            errx(EXIT_FAILURE, "invalid options");
        }

        opt = kLongOpts[longopt].name;

        if (strcmp(opt, "hdr-date") == 0) {
            patch->hdr.date = strtoul(optarg, NULL, 16);
        } else if (strcmp(opt, "hdr-revision") == 0) {
            patch->hdr.revision = strtoul(optarg, NULL, 0);
            patch->hdr.rev      = patch->hdr.revision;
        } else if (strcmp(opt, "hdr-revlow") == 0) {
            patch->hdr.revision &= 0xFFFFFF00;
            patch->hdr.revision |= strtoul(optarg, NULL, 0) & 0xFF;
            patch->hdr.rev      = patch->hdr.revision;
        } else if (strcmp(opt, "hdr-revinc") == 0) {
            patch->hdr.revision++;
            patch->hdr.rev      = patch->hdr.revision;
        } else if (strcmp(opt, "hdr-autorun") == 0) {
            if (strcmp(optarg, "true") == 0) {
                patch->hdr.options.autorun = true;
            } else if (strcmp(optarg, "false") == 0) {
                patch->hdr.options.autorun = false;
            } else {
                errx(EXIT_FAILURE, "did not understand autorun option %s", optarg);
            }
        } else if (strcmp(opt, "hdr-cpuid") == 0) {
            patch->hdr.cpuid    = strtoul(optarg, NULL, 0);
        } else if (strcmp(opt, "match") == 0) {
            set_match_registers(patch, optarg);
        } else if (strcmp(opt, "nop") == 0) {
            set_insn_nop(patch, optarg);
        } else if (strcmp(opt, "seq") == 0) {
            set_sequence_word(patch, optarg);
        } else if (strcmp(opt, "insn") == 0) {
            set_insn_value(patch, optarg);
        } else if (strcmp(opt, "insn-field") == 0) {
            set_insn_field(patch, optarg);
        } else if (strcmp(opt, "fastpath") == 0) {
            set_fastpath_hook(patch, optarg);
        } else {
            errx(EXIT_FAILURE, "BUG: option %s not handled", opt);
        }
    }

    // All options applied, now save the output
    save_patch_file(patch, argv[optind]);
    free_patch_file(patch);
    return 0;
}
