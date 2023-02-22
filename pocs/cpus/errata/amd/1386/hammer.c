#define _GNU_SOURCE
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <sched.h>
#include <syscall.h>
#include <x86intrin.h>
#include <sys/random.h>

int main(int argc, char **argv)
{
    cpu_set_t set;

    CPU_ZERO(&set);
    CPU_SET(1, &set);

    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        err(EXIT_FAILURE, "failed to set cpu affinity");
    }

    while (true) {
        sched_yield();
    }

    return 0;
}
