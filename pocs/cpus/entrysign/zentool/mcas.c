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

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <getopt.h>
#include <err.h>

#include "ucode.h"
#include "disas.h"
#include "risc86.h"
#include "parse.h"
#include "util.h"
#include "options.h"

struct globalopts options = {0};

static const struct option kLongOpts[] = {
    {          "help", false, NULL, 'h' },
    {       "verbose", false, &options.verbose, true },
    {         "quiet", false, &options.quiet, true },
    {         "debug", false, &options.debug, true },
    {0},
};

static const char *kOptHelp[] = {
    "print this message",
    "increase output for debugging",
    "decrease console output",
    "very verbose debugging",
};

static int print_usage(const char *name)
{
    logmsg("assemble a microcode program");
    print_usage_generic(name, "[ASSEMBLY]", kLongOpts, kOptHelp);
    logmsg("if ASSEMBLY is not provided, read instructions from STDIN");
    return 0;
}

int main(int argc, char **argv)
{
    int c, longopt;
    char *line = NULL;
    size_t size = 0;

    union BaseOp op = {0};

    // Make output verbose by default.
    options.verbose = true;

    // Now I can check for any settings the user wanted.
    while ((c = getopt_long(argc, argv, "h", kLongOpts, &longopt)) != -1) {
        switch (c) {
            case 'h': print_usage(*argv);
                      return 0;
            case '?': print_usage(*argv);
                      return 1;
        }
    }

    // If there was an instrction on the commandline, use that.
    if (optind == argc - 1) {
        if (zen_assemble_line(argv[optind], &op) == false) {
            errx(EXIT_FAILURE, "assembly failed");
        }

        if (options.quiet) {
            printf("%#018lX\n", op.val);
            return 0;
        }

        dump_op_disassembly(op);
        return 0;
    }

    dbgmsg("about to start reading from stdin");

    while (getline(&line, &size, stdin) > 0) {
        char *comment   = strchrnul(line, ';');
        char *label     = strchrnul(line, ':');
        char *newline   = strchrnul(line, '\n');
        size_t wspace   = strspn(line, " \t");

        // Remove any trailing newline
        *newline = '\0';

        dbgmsg("processing the line %s", line);

        // Remove any comment or label symbol.
        *comment = '\0';
        *label   = '\0';

        // Remove leading whitespace,.
        memmove(line, line + wspace, size - wspace);

        // Skip if this is a CPP or blank line
        if (*line == '#' || *line == '\0') {
            continue;
        }

        // If there is a ':' character before any comment, then this is a label.
        if (label < comment) {
            continue;
        }

        // Now we assemble the line
        if (zen_assemble_line(line, &op) == false) {
            errx(EXIT_FAILURE, "assembly failed at line `%s`", line);
        }

        dump_op_disassembly(op);
    }

    free(line);
    return 0;
}
