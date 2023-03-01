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

#if !defined(__AVX__)
# error You must compile this with -mavx to get the needed intrinsics
#endif

struct i387_fxsave_struct {
        uint16_t cwd; /* Control Word                    */
        uint16_t swd; /* Status Word                     */
        uint16_t twd; /* Tag Word                        */
        uint16_t fop; /* Last Instruction Opcode         */
        union {
            struct {
                uint64_t rip; /* Instruction Pointer             */
                uint64_t rdp; /* Data Pointer                    */
            };
            struct {
                uint32_t fip; /* FPU IP Offset                   */
                uint32_t fcs; /* FPU IP Selector                 */
                uint32_t foo; /* FPU Operand Offset              */
                uint32_t fos; /* FPU Operand Selector            */
            };
        };
        uint32_t mxcsr;          /* MXCSR Register State */
        uint32_t mxcsr_mask;     /* MXCSR Mask           */
        uint32_t st_space[32];
        uint32_t xmm_space[64];
        uint32_t padding[12];
        union {
            uint32_t padding1[12];
            uint32_t sw_reserved[12];
        };
} __attribute__((aligned(16)));

struct ymmh_struct {
        uint32_t ymmh_space[64];
};

struct xsave_hdr_struct {
        uint64_t xstate_bv;
        uint64_t reserved1[2];
        uint64_t reserved2[5];
} __attribute__((packed));

struct xsave_struct {
        struct i387_fxsave_struct i387;
        struct xsave_hdr_struct xsave_hdr;
        struct ymmh_struct ymmh;
} __attribute__ ((packed, aligned (64)));


int main(int argc, char **argv)
{
    cpu_set_t set;
    uint64_t count;
    static struct xsave_struct initial = {0};
    static struct xsave_struct xsave = {0};
    register __m128 a = _mm_setzero_ps();
    register __m128 b = _mm_setzero_ps();
    register __m128 c = _mm_set1_ps(2);

    CPU_ZERO(&set);
    CPU_SET(0, &set);

    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        err(EXIT_FAILURE, "failed to set cpu affinity");
    }

    // VSQRTSS followed by VZEROALL makes XSAVE non-deterministic.
    // Is this a bug?

    // Do a test execution just to record our XINUSE flags.
    asm volatile ("vsqrtss %0, %1, %2" : "=v"(c) : "v"(b), "v"(a));

    // Reset everything
    _mm256_zeroall();

    // Now fetch our XINUSE bitmap.
    _xsave(&initial, 0b11);

    fprintf(stderr, "first execution, our flags: %010lX\n",
                    initial.xsave_hdr.xstate_bv);

    for (count = 0;;count++) {
        asm volatile ("vsqrtss %0, %1, %2" : "=v"(c) : "v"(b), "v"(a));

        _mm256_zeroall();

        _xsave(&xsave, 0b11);

        if (xsave.xsave_hdr.xstate_bv != initial.xsave_hdr.xstate_bv) {
            fprintf(stderr, "After %0lu tests, our XINUSE was %010lx vs %010lx\n",
                            count,
                            xsave.xsave_hdr.xstate_bv,
                            initial.xsave_hdr.xstate_bv);
            break;
        }

    }

    return 0;
}
