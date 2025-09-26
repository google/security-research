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
#include <assert.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdarg.h>
#include <errno.h>
#include <err.h>

#include "util.h"
#include "options.h"


int print_usage_generic(const char *name, const char *param, const struct option *opts, const char **help)
{
    static const int kOptPadding = 16;

    if (name == NULL)
        name = program_invocation_short_name;

    puterr("%s [OPTIONS] %s", name, param);

    for (int i = 0; opts[i].name; i++) {
        int space = kOptPadding - strlen(opts[i].name);
        puterr("\t--%s%*c: %s", opts[i].name, space, ' ', help[i]);
    }

    return 0;
}

// This is a generic routine for handling arguments of the form foo=0,1,2,3-4
bool opt_num_inrange(const char *range, int num)
{
    char *r, *s, *e;

    // Example:
    // 1,2,3,4-8,2 or all

    if (range == NULL)
        return false;

    if (strcmp(range, "all") == 0)
        return true;

    s = strtok_r(strdupa(range), ",", &r);

    while (s) {
        int start;
        int end;

        start = end = strtoul(s, &e, 0);

        // We suppose a special syntax for addressing quads:
        //      q0      - everything in quad0
        //      q3i0    - first instruction of quad3
        if (*s == 'q' && *e == 'q') {
            if (*++s == '\0') {
                errx(EXIT_FAILURE, "expected a quad number after 'q' in %s", range);
            }

            // Find the quad number specified
            start = end = strtoul(s, &e, 10);

            // Multiple by 4 to get instruction number.
            end = start *= 4;

            // User wants a specific instruction.
            if (*e == 'i') {
                unsigned insn;

                if (*++e == '\0') {
                    errx(EXIT_FAILURE, "expected an index after qXi in %s, e.g. q3i2", range);
                }

                insn = strtoul(e, &e, 10);

                if (insn > 3) {
                    errx(EXIT_FAILURE, "there are only 4 instructions in a quad, so %u is out of range", insn);
                }

                // Add the requested offset.
                end = start += insn;
            } else if (*e == '\0') {
                // Nothing else, so user wants the entire quad.
                end += 3;
            }

            // Make sure we consumed the whole thing.
            if (*e != '\0') {
                errx(EXIT_FAILURE, "expected a quad spec after 'q' in %s, e.g. q3i2", range);
            }

            if (start < 0) {
                errx(EXIT_FAILURE, "expected a positive quad number in %s, e.g. q2i1", range);
            }
        }

        if (*e == '-') {
            // Increment past the '-'
            e++;

            // 2-,3- (all numbers after start)
            if (*e == '\0') {
                if (num >= start)
                    return true;
                // Unbounded range, but no match.
                goto next;
            }

            // 2-4,2-5 (all numbers between range)
            end = strtoul(e, &e, 0);
        }

        if (*e != '\0' || end < start) {
            errx(EXIT_FAILURE, "The range %s was not valid (example: 1,2,3,4-5)", s);
        }

        // 2-3,4-5 (all numbers between range)
        if (num >= start && num <= end)
            return true;

      next:
        s = strtok_r(NULL, ",", &r);
    }

    return false;
}

bool opt_num_parse(const char *value, uint64_t *result)
{
    return opt_num_parse_max(value, result, UINT64_MAX);
}

bool opt_num_parse_max(const char *value, uint64_t *result, uint64_t max)
{
    char *end;

    dbgmsg("attempting to parse a number from the string %s (limit=%#lx)", value, max);

    // Verify there was an '=foo'
    if (value == NULL || *value == '\0') {
        dbgmsg("the string was empty, parsing failed");
        return false;
    }

    *result = strtoul(value, &end, 0);

    if (*end != '\0') {
        dbgmsg("the string was not a valid number, parsing stopped at %s", end);
        return false;
    }

    if (*result > max) {
        dbgmsg("the number %ld was valid, but exceeded the specified range", *result);
        return false;
    }

    return true;
}
