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

#if !defined(__AVX512VL__)
# error You must compile this with -mavx512vl to get the needed intrinsics
#endif

static const uint64_t kData[] = { 0x4444444444444444, 0x4242424242424242 };
static const uint64_t kZero;

static void vmovhps_testcase()
{
    uint64_t result[2] __aligned = {0};
    register __m128i r0  asm("xmm0");
    register __m128i r1  asm("xmm1");
    register __m128i r17 asm("xmm17");
    uint64_t count = 0;

    _mm256_zeroall();

    do {
        count++;

        // Trigger bug
        asm volatile ("vmovdqu %1, %0"      : "=v"(r0)  : "m"(kData));
        asm volatile ("vmovlps %2, %1, %0"  : "=v"(r1)  : "v"(r0), "m"(kZero));
        asm volatile ("vmovhps %2, %1, %0"  : "=v"(r17) : "v"(r0), "m"(kZero));
    } while (!_mm_testz_si128(r1, r1));

    _mm_storeu_si128((void *) result, r1);

    fprintf(stderr, "After %llu: %016llx, %016llx\n", count, result[0], result[1]);
    return;
}

int main(int argc, char **argv)
{
    while (true) {
        vmovhps_testcase();
    }
    return 0;
}
