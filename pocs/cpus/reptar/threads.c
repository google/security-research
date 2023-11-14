#define _GNU_SOURCE
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <sched.h>
#include <syscall.h>
#include <err.h>
#include <pthread.h>
#include <assert.h>
#include <ctype.h>
#include <signal.h>
#include <sys/sysinfo.h>

#include "threads.h"

// This wrapper spawns a thread locked to a specific CPU.
pthread_t spawn_thread_core(void *(*start_routine)(void *), void *restrict arg, int cpu)
{
    pthread_t tid = 0;
    pthread_attr_t attr;
    cpu_set_t set;

    // Unspecified
    if (cpu < 0 || !start_routine)
        return tid;

    pthread_attr_init(&attr);
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);

    if (pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &set) != 0)
        err(EXIT_FAILURE, "failed to lock thread to specified core %d", cpu);
    if (pthread_create(&tid, &attr, start_routine, arg) != 0)
        err(EXIT_FAILURE, "failed to start thread on specifed core %d", cpu);
    pthread_attr_destroy(&attr);
    return tid;
}

int set_cpu_affinity(int cpu)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);

    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        err(EXIT_FAILURE, "failed to set cpu affinity");
    }
    return 0;
}
