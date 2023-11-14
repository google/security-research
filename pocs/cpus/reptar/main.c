#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <pthread.h>
#include <sched.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <x86intrin.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <err.h>

#include "threads.h"
#include "util.h"

extern uint64_t icelake_repro();
extern uint64_t sibling_trigger();

static void * icelake_worker(void *param)
{
    // Need to enable cancellation.
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

    icelake_repro();

    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

    return 0;
}

static void * icelake_hammer(void *param)
{
    // Need to enable cancellation.
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

    sibling_trigger();

    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

    return 0;
}

static void print_help()
{
    logmsg("usage: ./icebreak [OPTIONS]");
    logmsg("    -c N,M      Run repro threads on core N and M.");
    logmsg("    -d N        Sleep N usecs between repro attempts.");
    logmsg("    -H N        Spawn a hammer thread on core N.");
}

static struct rlimit rlim = {
    .rlim_cur = 0,
    .rlim_max = 0,
};

static int delay = 1000;

int main(int argc, char **argv)
{
    pthread_t A = 0, B = 0;
    pthread_t hammer = 0;
    int coreA = -1;
    int coreB = -1;
    int opt;
    int coreH = -1;
    pid_t child;

    setrlimit(RLIMIT_CORE, &rlim);

    while ((opt = getopt(argc, argv, "H:hc:d:")) != -1) {
        switch (opt) {
            case 'c': if (sscanf(optarg, "%u,%u", &coreA, &coreB) != 2)
                        errx(EXIT_FAILURE, "the format required is N,M, for example: 0,1");
                      break;
            case 'd': delay = atoi(optarg);
                      break;
            case 'H': coreH = atoi(optarg);
                      break;
            case 'h': print_help();
                      break;
            default:
                print_help();
                errx(EXIT_FAILURE, "unrecognized commandline argument");
        }
    }

    if (coreA < 0 || coreB < 0) {
        errx(EXIT_FAILURE, "you must at least specify a core pair with -c! (see -h for help)");
    }

    if (coreH >= 0) {
        hammer = spawn_thread_core(icelake_hammer, NULL, coreH);
        logmsg("Hammer thread %p on core %d", hammer, coreH);
    }

    logmsg("starting repro on cores %d and %d", coreA, coreB);

    do {
        // Run this in a subprocess in case it crashes.
        if ((child = fork()) == 0) {

            // Make sure it doesn't get stuck if it jumps into an infinite loop.
            alarm(5);

            // Attempt to repro 64 times.
            for (int i = 0; i < 64; i++) {
                if (!A || pthread_tryjoin_np(A, NULL) == 0)
                    A = spawn_thread_core(icelake_worker, NULL, coreA);
                if (!B || pthread_tryjoin_np(B, NULL) == 0)
                    B = spawn_thread_core(icelake_worker, NULL, coreB);

                usleep(delay);
                fputc('.', stderr);
            }

            // No luck, it might be in a weird state - restart.
            pthread_cancel(A);
            pthread_cancel(B);

            fputc('\n', stderr);

            pthread_join(A, NULL);
            pthread_join(B, NULL);

            _exit(0);
        }
    } while (waitpid(child, NULL, 0) != -1);

    err(EXIT_FAILURE, "this is supposed to be unreachable, waitpid() failed");

    return 0;
}
