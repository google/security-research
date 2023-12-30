#define _GNU_SOURCE
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <x86intrin.h>
#include <immintrin.h>
#include <sched.h>
#include <syscall.h>
#include <err.h>

#define __aligned __attribute__((aligned(32)))

static uint64_t vpinsrw_testcase(uint64_t *correct)
{
    uint64_t regstate[2] __aligned = {0};
    register __m128i r1 asm("xmm13");

    _mm256_zeroall();

    // Record stack pointer so we know the correct value.
    asm volatile ("mov %%rsp, %0" : "=m"(*correct));

    // Trigger bug
    asm volatile (".intel_syntax noprefix           \n"
                  // The bug is that these stack operations are ignored by the vmovq.
                  "push     rax                     \n"     // stack += 8
                  "pop      rax                     \n"     // stack -= 8
                  //"{evex} vmovq xmm13, rsp        \n"
                  ".byte 0x62                       \n"     // evex
                  //       RXBR00mm
                  ".byte 0b00110001                 \n"     // P0
                  //       Wvvvv1pp
                  ".byte 0b11111101                 \n"     // P1
                  //       zLLbVaaa
                  ".byte 0b00001000                 \n"     // P2
                  ".byte 0x6e, 0xec                 \n"     // movq
                  ".att_syntax prefix               \n"
    );

    // Grab the first word, which should be equal to sp, right?
    _mm_storeu_si128((void *) regstate, r1);
    return regstate[0];
}

int main(int argc, char **argv)
{
    uint64_t correct;
    uint64_t result;

    for (uint64_t i = 0 ;; i++) {
        result = vpinsrw_testcase(&correct);

        if (correct != result) {
            fprintf(stderr, "after %llu: %#x vs %#x\n", i, result, correct);
        }
    }
    return 0;
}
