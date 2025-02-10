#include <err.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <x86intrin.h>

#define fatal(...) err(EXIT_FAILURE, __VA_ARGS__)
#define fatalx(...) errx(EXIT_FAILURE, __VA_ARGS__)

static bool rdrand64(uint64_t *v)
{
        for (int i = 0; i < 10; i++) {
                bool ok;
                asm volatile("rdrand %0\n\t" : "=r" (*v), "=@ccc" (ok));
                if (ok) {
                        return true;
                }
        }

        return false;
}

int main(void)
{
        uint64_t rands[10];

        for (uint64_t i = 0; i < 10; i++) {
                if (!rdrand64(&rands[i])) {
                        fatalx("rdrand failed and returned %lx", rands[i]);
                }

                for (uint64_t ii = 0; ii < i; ii++) {
                        if (rands[i] == rands[ii]) {

                                fprintf(stderr, "repeated value!\n");
                                for (uint64_t iii = 0; iii <= i; iii++) {
                                        printf("0x%lx\n", rands[iii]);
                                }
                                exit(EXIT_FAILURE);
                        }
                }
        }

        puts("rdrand ok");
}
