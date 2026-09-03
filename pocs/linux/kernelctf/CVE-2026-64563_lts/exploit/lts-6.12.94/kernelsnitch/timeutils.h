#pragma once

#define _GNU_SOURCE
#include <sched.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#if !defined(__ARM) && !defined(__INTEL) && !defined(__AMD)
#define __INTEL
#endif

#define RDPRU ".byte 0x0f, 0x01, 0xfd"
#define RDPRU_ECX_MPERF 0
#define RDPRU_ECX_APERF 1

static inline size_t rdtsc_begin(void)
{
#if defined(__INTEL)
    size_t a, d;
    asm volatile("mfence");
    asm volatile("rdtsc" : "=a"(a), "=d"(d));
    a = (d << 32) | a;
    asm volatile("lfence");
    return a;
#elif defined(__AMD)
    unsigned long low_a, high_a;
    asm volatile("mfence");
    asm volatile(RDPRU : "=a"(low_a), "=d"(high_a) : "c"(RDPRU_ECX_APERF));
    unsigned long aval = ((low_a) | (high_a) << 32);
    asm volatile("lfence");
    return aval;
#elif defined(__ARM)
    unsigned long long vct;
    asm volatile("isb" ::: "memory");
    asm volatile("mrs %0, cntvct_el0" : "=r"(vct));
    asm volatile("isb" ::: "memory");
    return (size_t)vct;
#else
#error "Invalid TIMEUTILS_ARCH value"
#endif
}

static inline size_t rdtsc_end(void)
{
#if defined(__INTEL)
    size_t a, d;
    asm volatile("lfence");
    asm volatile("rdtsc" : "=a"(a), "=d"(d));
    a = (d << 32) | a;
    asm volatile("mfence");
    return a;
#elif defined(__AMD)
    unsigned long low_a, high_a;
    asm volatile("lfence");
    asm volatile(RDPRU : "=a"(low_a), "=d"(high_a) : "c"(RDPRU_ECX_APERF));
    unsigned long aval = ((low_a) | (high_a) << 32);
    asm volatile("mfence");
    return aval;
#elif defined(__ARM)
    unsigned long long vct;
    asm volatile("isb" ::: "memory");
    asm volatile("mrs %0, cntvct_el0" : "=r"(vct));
    asm volatile("isb" ::: "memory");
    return (size_t)vct;
#else
#error "Invalid TIMEUTILS_ARCH value"
#endif
}
