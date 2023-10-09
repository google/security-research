#define _GNU_SOURCE
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <sched.h>
#include <syscall.h>
#include <x86intrin.h>
#include <sys/random.h>
#include <err.h>

int main(int argc, char **argv)
{
    cpu_set_t set;

    CPU_ZERO(&set);
    CPU_SET(0, &set);

    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        err(EXIT_FAILURE, "failed to set cpu affinity");
    }

    while (true) {
#if defined(__AVX__)
        register __m128 a = _mm_setzero_ps();
        register __m128 b = _mm_setzero_ps();
        register __m128 c = _mm_set1_ps(2);
        asm volatile ("pause");
        asm volatile ("fninit");
        asm volatile ("fldpi");
        asm volatile ("vsqrtss %0, %1, %2" : "=v"(c) : "v"(b), "v"(a));
        _mm256_zeroall();
#endif
        asm volatile ("syscall" :: "a"(SYS_sched_yield) : "rcx", "r11");
    }

    return 0;
}
