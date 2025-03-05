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
#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>
#include <string.h>
#include <err.h>

#include "ucode.h"
#include "risc86.h"
#include "options.h"
#include "disas.h"
#include "fields.h"
#include "util.h"

struct globalopts options = {0};

static const struct option kLongOpts[] = {
    {          "help", false, NULL, 'h' },
    {           "set",  true, NULL, false },
    {       "verbose", false, &options.verbose, true },
    {         "quiet", false, &options.quiet, true },
    {         "debug", false, &options.debug, true },
    {0},
};

static const char *kOptHelp[] = {
    "print this message",
    "set field=Y, e.g. reg2=0x123",
    "increase output for debugging",
    "decrease console output",
    "very verbose debugging",
};

static int print_usage(const char *name)
{
    logmsg("disassemble or modify a microcode instruction");
    print_usage_generic(name, "OPCODE", kLongOpts, kOptHelp);
    return 0;
}

int main(int argc, char **argv)
{
    int longopt;
    int c;
    char *end;
    char *opcode;
    union BaseOp op = {0};

    // Make output verbose by default.
    options.verbose = true;

    // There must at least be a hex number specified
    if (argc < 2) { print_usage(*argv); return 1; }

    // The last parameter should be the opcode we're supposed to decode.
    opcode = argv[argc - 1];

    // I need the number before I can parse options, so do that now...
    op.val = strtoul(opcode, &end, 16);

    // Check that worked...
    if (*opcode == '\0' || *end != '\0') {
        print_usage(*argv);
        errx(EXIT_FAILURE, "expected a hex number to disassemble");
    }

    // Now I can check for any settings the user wanted.
    while ((c = getopt_long(argc, argv, "h", kLongOpts, &longopt)) != -1) {
        const char *opt;

        switch (c) {
            case 'h': print_usage(*argv);
                      return 0;
            case '?': print_usage(*argv);
                      return 1;
            case   0:
                opt = kLongOpts[longopt].name;

                if (strcmp(opt, "set") == 0) {
                    char *field = strdupa(optarg);
                    char *value = strchr(field, '=');
                    uint64_t num;

                    if (value == NULL) {
                        errx(EXIT_FAILURE, "you didnt specify a value, e.g. type=0x1234");
                    }

                    // Remove the =, making field and value both nul terminated.
                    *value++ = '\0';

                    if (opt_num_parse(value, &num) == false) {
                        errx(EXIT_FAILURE, "failed to parse the number %s", value);
                    }

                    if (set_field_name(&op, field, num) == false) {
                        errx(EXIT_FAILURE, "unable to set the specified fieldname");
                    }
                    break;
                }
        }
    }

    // The only way to reach here would be if the last parameter was part of an
    // option.
    if (optind != argc - 1) {
        print_usage(*argv);
        errx(EXIT_FAILURE, "invalid arguments specified");
    }

    dump_op_disassembly(op);

    return 0;
}
