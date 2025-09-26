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
#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>
#include <immintrin.h>

#include "ucode.h"

// This is just for testing, ignore warnings
#pragma GCC diagnostic ignored "-Wanalyzer-unsafe-call-within-signal-handler"

typedef struct {
    uint64_t gprs[16];
    uint64_t rflags;
    uint64_t padding[3];
    __m256i ymms[16];
} cpu_state_t;

extern const char *check_opcode_results(cpu_state_t *state);
extern const char *lastexec;

cpu_state_t cpu_state __attribute((aligned(256)));

void print_rflags(const char flags) {
    if (flags & 0x1) printf("CF ");
    if (flags & 0x4) printf("PF ");
    if (flags & 0x10) printf("AF ");
    if (flags & 0x40) printf("ZF ");
    if (flags & 0x80) printf("SF ");
    if (flags & 0x100) printf("TF ");
    if (flags & 0x200) printf("IF ");
    if (flags & 0x400) printf("DF ");
    if (flags & 0x800) printf("OF ");
    printf("\n");
}

void print_results(const char *name)
{
    printf("%s\n", name);
    for (uint32_t i = 0; i < 16; i++) {
        printf("  GPR[%d]: 0x%016lx (%s)\n", i, cpu_state.gprs[i], (char *)&cpu_state.gprs[i]);
    }
    printf("  RFLAGS(pre) : 0x%016lx - ", cpu_state.gprs[14]);
    print_rflags(cpu_state.gprs[14]);
    printf("  RFLAGS(post): 0x%016lx - ", cpu_state.gprs[15]);
    print_rflags(cpu_state.gprs[15]);

    for (uint32_t i = 0; i < 16; i++) {
        printf("  YMM[%d]: %08lX:%08lX:%08lX:%08lX\n", i,
            ((uint64_t *)&cpu_state.ymms[i])[0],
            ((uint64_t *)&cpu_state.ymms[i])[1],
            ((uint64_t *)&cpu_state.ymms[i])[2],
            ((uint64_t *)&cpu_state.ymms[i])[3]);
    }
}

void handler(int n)
{
    (void) n;
    print_results(lastexec);
    exit(0);
}

int main(int argc, char **argv)
{
    const char *result;

    (void) argc, (void) argv;

    signal(SIGILL,  handler);
    signal(SIGSEGV, handler);
    signal(SIGFPE,  handler);
    signal(SIGTRAP, handler);

    result = check_opcode_results(&cpu_state);

    if (result) {
        print_results(lastexec);
    }

    return 0;
}
