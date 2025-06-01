/* Copyright (c) 2025, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/prctl.h> /* Definition of PR_* constants */
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ucontext.h>
#include <unistd.h>

uint64_t time_load(const void *addr);

#if defined(__x86_64__)

#include <x86intrin.h>

#define mfence() asm volatile("mfence" ::: "memory")
#define clflush(x) _mm_clflush(x)
#define USERPAGE_MASK 0x00007FFFffffF000ull

#elif defined(__aarch64__)

#define mfence() asm volatile("dsb sy" ::: "memory")
#define clflush(x) asm volatile("dc civac, %0" ::"r"(x) : "memory")
#define USERPAGE_MASK 0x0000FFFFffffF000ull

#endif

uint32_t xorshift128();
uint64_t get_rand64();
void* alloc_pages_at(uint64_t r, size_t sz);
void* alloc_page_at(uint64_t r);
void* alloc_random_page_(uint64_t and_with, uint64_t or_with);
void* alloc_random_pages_(uint64_t and_with, uint64_t or_with, size_t sz);
void* alloc_random_page();
void* alloc_random_pages(size_t sz);

void init(int argc, char** argv);

uint64_t virt_to_phys(const void *addr);
void shuffle(uint64_t *array, size_t n);
int open_mod();
void flush_kernel_address(int fd, uint64_t addr);
