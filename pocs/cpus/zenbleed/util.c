#define _GNU_SOURCE
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <pthread.h>
#include <err.h>
#include <assert.h>
#include <stdarg.h>

#include "zenbleed.h"

bool quiet;

void logmsg(char *format, ...)
{
    va_list ap;
    // Try to limit console noise.
    if (quiet == true)
        return;

    // Print a debugging message.
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    fputc('\n', stderr);
    va_end(ap);
    return;
}

void print(char *format, ...)
{
    va_list ap;
    // Try to limit console noise.
    if (quiet == true)
        return;

    // Print a debugging message.
    va_start(ap, format);
    vfprintf(stdout, format, ap);
    va_end(ap);
    return;
}

bool num_inrange(char *range, int num)
{
    char *r, *s, *e;

    // Example:
    // 1,2,3,4-8,2

    if (range == NULL)
        return false;

    s = strtok_r(strdupa(range), ",", &r);

    while (s) {
        int start;
        int end;

        start = end = strtoul(s, &e, 0);

        if (*e == '-') {
            end = strtoul(++e, &e, 0);
        }

        if (*e != '\0' || end < start) {
            errx(EXIT_FAILURE, "The range %s was not valid (example: 1,2,3,4-5)", s);
        }

        if (num >= start && num <= end)
            return true;

        s = strtok_r(NULL, ",", &r);
    }

    return false;
}
