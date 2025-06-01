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

#define optional optional_argument

struct globalopts options = {0};

static const struct option kLongOpts[] = {
    {          "help", false, NULL, 'h' },
    {        "output",  true, NULL, 'o' },
    {       "version", false, NULL, 'V' },
    {       "verbose", false, &options.verbose, true },
    {         "quiet", false, &options.quiet, true },
    {         "debug", false, &options.debug, true },
    {0},
};


static const char *kOptHelp[] = {
    "print this message",
    "choose output filename",
    "print version",
    "increase output for debugging",
    "decrease console output",
    "very verbose debugging",
};

static const struct subcmds kSubcmds[] = {
    {       "help",   cmd_help_main,        "List available subcommands" },
    {      "print",   cmd_dump_main,             "Decode an update file" },
    {     "resign", cmd_factor_main,        "Fix an incorrect signature" },
    {       "load",   cmd_load_main,   "Load an update file onto a core" },
    {       "edit",   cmd_edit_main, "Modify contents of an update file" },
    {     "verify", cmd_verify_main,      "Validate and check signature" },
    {    "encrypt",  cmd_crypt_main,            "Encrypt an update file" },
    {    "decrypt",  cmd_crypt_main,            "Decrypt an update file" },
    {   "preimage",  cmd_fixup_main,    "Try alternate signing strategy" },
    {    "version",    cmd_ver_main,             "Print current version" },
    {      "crypt",  cmd_crypt_main,                                NULL },
    {       "dump",   cmd_dump_main,                                NULL },
    {      "fixup", cmd_factor_main,                                NULL },
    {0},
};

static int print_version()
{
    putmsg("zentool %s - view and edit cpu microcode updates", ZENTOOL_VERSION);
    logmsg("                                        by taviso@");
    return 0;
}

static int print_usage(const char *name)
{
    print_version();
    print_usage_generic(name, "CMD [SUBOPTIONS...] [INPUT]", kLongOpts, kOptHelp);
    return 0;
}

int main(int argc, char **argv)
{
    int longopt;
    int c;

    while ((c = getopt_long(argc, argv, "+i:o:hvV", kLongOpts, &longopt)) != -1) {
        switch (c) {
            case 'o': options.outfile = optarg;
                      break;
            case 'h': print_usage(*argv);
                      logmsg("Use `zentool help` for available subcommands.");
                      return 0;
            case 'V': print_version();
                      return 0;
            case '?': print_usage(*argv);
                      errx(EXIT_FAILURE, "invalid options");
        }
    }

    // Must at least provide a command name
    if (optind == argc) {
        print_usage(*argv);
        errx(EXIT_FAILURE, "must provide a command, try `help`");
    }

    for (const struct subcmds *s = kSubcmds;; s++) {
        if (s->name == NULL) {
            errx(EXIT_FAILURE, "unrecognized command `%s`, try `help`", argv[optind]);
        }

        if (strcmp(s->name, argv[optind]) == 0) {
            if (s->handler(argc - optind, &argv[optind]) != 0) {
                dbgmsg("command %s returned failure", s->name);
                return EXIT_FAILURE;
            }

            break;
        }
    }

    return 0;
}

int cmd_help_main(int argc, char **argv)
{
    print_usage(NULL);

    (void) argc, (void) argv;

    logmsg("");
    logmsg("The following subcommands are available:");

    for (const struct subcmds *s = kSubcmds; s->name; s++) {
        // If the description is empty, dont print it. This allows making
        // simple aliases without cluttering the list.
        if (s->description == NULL)
            continue;

        putmsg("\t%-8s : %s", s->name, s->description);
    }
    return 0;
}

int cmd_ver_main(int argc, char **argv)
{
    (void) argc, (void) argv;

    return print_version();
}
