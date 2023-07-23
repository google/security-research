#define _GNU_SOURCE
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <pthread.h>
#include <err.h>
#include <assert.h>

#include "zenbleed.h"

#define MAX_WORKQUEUE_SZ 8192

static struct zenleak * workqueue[MAX_WORKQUEUE_SZ];
static uint64_t count;

static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;  // workqueue lock
static pthread_cond_t  c = PTHREAD_COND_INITIALIZER;   // workqueue available
static pthread_cond_t  f = PTHREAD_COND_INITIALIZER;   // workqueue full

int save_new_leak(struct zenleak *leak)
{
    assert(leak);

    // We're about to insert an item into the queue, so take the lock.
    pthread_mutex_lock(&m);

    // Wait here if the queue is full.
    while (count >= MAX_WORKQUEUE_SZ) {
        pthread_cond_wait(&f, &m);
    }

    // Insert into queue.
    workqueue[count++] = leak;

    // All done, release lock.
    pthread_mutex_unlock(&m);

    // Wake up consumer thread.
    pthread_cond_signal(&c);

    return 0;
}

struct zenleak * load_new_leak(void)
{
    struct zenleak *leak;

    pthread_mutex_lock(&m);

    // Wait for a leaker to produce some work.
    while (count == 0) {
        pthread_cond_wait(&c, &m);
    }

    // Remove item from the top.
    leak = workqueue[--count];

    // Signal any workers that the queue has capacity.
    pthread_cond_signal(&f);
    pthread_mutex_unlock(&m);

    assert(leak);

    return leak;
}
