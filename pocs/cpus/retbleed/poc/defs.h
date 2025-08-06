/* SPDX-License-Identifier: GPL-3.0-only */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdnoreturn.h>
#include <string.h>

/* Misc typedefs and compiler definitions */

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;

#ifndef __always_inline
#define __always_inline inline __attribute__ ((always_inline))
#endif

#define __never_inline __attribute__ ((noinline))
#define __never_optimize __attribute__((optimize(0)))
#define UNUSED(x) ((void)x)

#define MIN(x, n) ((x) > (n) ? (n) : (x))
#define ARRAY_SIZE(a) (sizeof(a) / (sizeof((a)[0])))

// Kernel text base without KASLR.
#define KERNEL_BASE 0xffffffff81000000ul
// Highest possible kernel text base.
#define KBASE_END 0xffffffffbe000000ul
