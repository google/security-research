/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdarg.h>
#include <assert.h>
#include <stdlib.h>
#include <getopt.h>
#include <ctype.h>
#include <err.h>

#include "util.h"
#include "options.h"

void logdbg(const char *prefix, const char *format, ...)
{
    va_list ap;

    // Try to limit console noise.
    if (options.debug == false)
        return;

    // Print a debugging message.
    fprintf(stderr, "debug:%s:", prefix);
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    fputc('\n', stderr);
    va_end(ap);

    return;
}

void logstr(const char *format, ...)
{
    va_list ap;

    // Try to limit console noise.
    if (options.quiet == true)
        return;

    // Print a debugging message.
    va_start(ap, format);
    vfprintf(stdout, format, ap);
    va_end(ap);

    return;
}

void putstr(const char *format, ...)
{
    va_list ap;

    // Print a debugging message.
    va_start(ap, format);
    vfprintf(stdout, format, ap);
    va_end(ap);

    return;
}

void logmsg(const char *format, ...)
{
    va_list ap;

    // Try to limit console noise.
    if (options.quiet == true)
        return;

    // Print a debugging message.
    va_start(ap, format);
    vfprintf(stdout, format, ap);
    fputc('\n', stdout);
    va_end(ap);

    return;
}

void putmsg(const char *format, ...)
{
    va_list ap;

    // Print a debugging message.
    va_start(ap, format);
    vfprintf(stdout, format, ap);
    fputc('\n', stdout);
    va_end(ap);

    return;
}

void logerr(const char *format, ...)
{
    va_list ap;

    // Try to limit console noise.
    if (options.quiet == true)
        return;

    // Print a debugging message.
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    fputc('\n', stderr);
    va_end(ap);

    return;
}

void puterr(const char *format, ...)
{
    va_list ap;

    // Print a debugging message.
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    fputc('\n', stderr);
    va_end(ap);

    return;
}


void loghex(const void *data, size_t size)
{
    char ascii[17] = {0};
    size_t i, j;

    const uint8_t *inp = data;

    for (i = 0; i < size; ++i) {

        printf("%02X ", inp[i]);

        if (isprint(inp[i])) {
            ascii[i % 16] = inp[i];
        } else {
            ascii[i % 16] = '.';
        }

        if ((i+1) % 8 == 0 || i+1 == size) {
            printf(" ");

            if ((i+1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';

                if ((i+1) % 16 <= 8) {
                    printf(" ");
                }

                for (j = (i+1) % 16; j < 16; ++j) {
                    printf("   ");
                }

                printf("|  %s \n", ascii);
            }
        }
    }
}

char** str_split(char* a_str, const char a_delim)
{
    char** result    = 0;
    size_t count     = 0;
    char* tmp        = a_str;
    char* last_comma = 0;
    char delim[2];
    delim[0] = a_delim;
    delim[1] = 0;

    /* Count how many elements will be extracted. */
    while (*tmp)
    {
        if (a_delim == *tmp)
        {
            count++;
            last_comma = tmp;
        }
        tmp++;
    }

    /* Add space for trailing token. */
    count += last_comma < (a_str + strlen(a_str) - 1);

    /* Add space for terminating null string so caller
       knows where the list of returned strings ends. */
    count++;

    result = malloc(sizeof(char*) * count);

    if (result)
    {
        size_t idx  = 0;
        char* token = strtok(a_str, delim);

        while (token)
        {
            assert(idx < count);
            *(result + idx++) = strdup(token);
            token = strtok(0, delim);
        }
        assert(idx == count - 1);
        *(result + idx) = 0;
    }

    return result;
}
