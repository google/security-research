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
#include <signal.h>
#include <sys/user.h>
#include <getopt.h>
#include <err.h>

#include "util.h"
#include "options.h"

struct globalopts options = {0};

static int dumpmode;
static int testmode;
static int showflags;

static const uint64_t kDefaultMagic = 0x5345435245543432ULL;
static uint64_t magic = kDefaultMagic;

static const struct option kLongOpts[] = {
    {          "help", false, NULL, 'h' },
    {       "version", false, NULL, 'v' },
    {          "dump", false, &dumpmode, true },
    {          "test", false, &testmode, true },
    {       "verbose", false, &options.verbose, true },
    {         "quiet", false, &options.quiet, true },
    {         "debug", false, &options.debug, true },
    {         "flags", false, &showflags, true },
    {        "secret",  true, NULL, 's' },
    {        "eflags",  true, NULL, 'f' },
    {0},
};

static const char *kOptHelp[] = {
    "print this message",
    "display version number",
    "dump mode -- raw binary output with incrementing index",
    "test mode -- try a few test arithmetic operations",
    "increase output for debugging",
    "decrease console output",
    "very verbose debugging",
    "show eflags after callback",
    "set the magic constant in @magic (used for testing)",
    "set eflags before callback",
};

static int print_version()
{
    logmsg("mtalk v0.01");
    return 0;
}

static int print_usage()
{
    logmsg("Helper program for communicating with microcode.");

    print_usage_generic(NULL, "PARAMS...", kLongOpts, kOptHelp);

    logmsg("");
    logmsg("mtalk will call the `fpatan` instruction with uint64_t parameters\n"
           "for example:                                                   \n\n"
           " $ mtalk 0x123 0x456                                           \n\n"
           "This will call @fpatan with 0x123 in RAX and 0x456 in RBX, and   \n"
           "print any result returned by fpatan in RAX.                      \n"
           "\n"
           "There are two alternative modes, --test and --dump.            \n\n"
           "    --test is used for figuring out what an unknown opcode does, \n"
           "           it will call fpatan with a test vector designed to    \n"
           "           reveal clues about what it did.                     \n\n"
           "    --dump will call fpatan repeatedly with an incrementing      \n"
           "           index in RAX, it is used for exploring what is in a   \n"
           "           memory region.                                        \n"
           "           call it with a start and stop address.                \n");

    return 0;
}

int unreachable()
{
    static const char message[] = "this code is unreachable.... unless? :-)\n";
    write(STDOUT_FILENO, message, sizeof(message) - 1);
    _exit(0);
}

static inline uint64_t invoke_microcode_callback(uint64_t arg1, uint64_t arg2, uint64_t flags)
{
    uint64_t result = 0;
    char flagstr[8] = {0};

    asm volatile (
            "push   %%rcx       \n"
            "popfq              \n"
            "fpatan             \n"
            "pushfq             \n"
            "pop    %%rcx       \n"
                    : "=a"(result), "=c"(flags)
                    : "a"(arg1), "b"(arg2), "c"(flags)
#ifndef __clang__
                    : "st(1)"
#endif
    );

    flagstr[0] = (flags & 0b00000001) ? 'C' : 'c';
    flagstr[1] = (flags & 0b00000100) ? 'P' : 'p';
    flagstr[2] = (flags & 0b00010000) ? 'A' : 'a';
    flagstr[3] = (flags & 0b01000000) ? 'Z' : 'z';
    flagstr[4] = (flags & 0b10000000) ? 'S' : 's';

    if (showflags)
        logmsg("flags %s", flagstr);

    return result;
}

uint64_t arith_test_vectors[][2] = {
    { 0x4141414141414141, 0x4242424242424242 },
    { 0x0000000000000010, 0x0000000000000020 },
    { 0x0000000000000020, 0x0000000000000010 },
    { 0x7777777777777777, 0x7777777777777777 },
    { 0x0000000000000000, 0x0000000000000001 },
    { 0x0000000000000001, 0x0000000000000001 },
    { 0x0000000000000001, 0xffffffffffffffff },
    { 0x1010101010101010, 0x0101010101010101 },
    { 0x5555555555555555, 0xaaaaaaaaaaaaaaaa },
    { 0x2020202020202020, 0x4040404040404040 },
    { 0x1010101010101010, 0x1818181818181818 },
};

// # Run this code
// $ taskset -c 2 ./mtalk
//
int main(int argc, char **argv)
{
    int c, longopt;
    uint64_t result;
    uint64_t param1 = 0;
    uint64_t param2 = 0;
    uint64_t flags = 0;

    // Check for any settings the user wanted.
    while ((c = getopt_long(argc, argv, "hs:f:", kLongOpts, &longopt)) != -1) {
        switch (c) {
            case 'h': print_usage();
                      return 0;
            case 'v': print_version();
                      return 0;
            case 'f': flags = strtoul(optarg, NULL, 0);
                      break;
            case '?': print_usage();
                      return 1;
            case 's': magic = strtoul(optarg, NULL, 0);
                      break;
        }
    }

    // This is mtalk a b
    if (argc - optind >= 1) {
        param1 = strtoul(argv[optind + 0], NULL, 0);

        // A fixed address used for testing
        if (strcmp(argv[optind + 0], "@magic") == 0)
            param1 = (uint64_t) &magic;
    }

    if (argc - optind >= 2) {
        param2 = strtoul(argv[optind + 1], NULL, 0);

        // A fixed address used for testing
        if (strcmp(argv[optind + 1], "@magic") == 0)
            param2 = (uint64_t) &magic;
    }

    if (dumpmode) {
        uint64_t start = param1;
        uint64_t stop  = param2;
        // in dump mode, param1 = start, param2 = stop
        for (uint64_t addr = start; addr < stop; addr += sizeof(result)) {
            result = invoke_microcode_callback(addr, sizeof(result), flags);
            fwrite(&result, sizeof(result), 1, stdout);
        }
        return 0;
    }

    if (testmode) {
        for (size_t i = 0; i < ARRAY_SIZE(arith_test_vectors); i++) {
            result = invoke_microcode_callback(arith_test_vectors[i][0], arith_test_vectors[i][1], flags);

            logmsg("%016lx ? %016lx = %016lx", arith_test_vectors[i][0], arith_test_vectors[i][1], result);
        }

        return 0;
    }


    result = invoke_microcode_callback(param1, param2, flags);

    if (magic != kDefaultMagic) {
        logmsg("%016lx + %016lx = %016lx magic %016lx", param1, param2, result, magic);
    } else {
        logmsg("%016lx + %016lx = %016lx", param1, param2, result);
    }

    return 0;
}
