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
#include <libgen.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <assert.h>
#include <stdlib.h>
#include <getopt.h>
#include <limits.h>
#include <unistd.h>
#include <err.h>
#include <json.h>

#include "util.h"
#include "ucode.h"
#include "risc86.h"
#include "crypt.h"
#include "parse.h"
#include "options.h"
#include "data.h"

static const char * typenames[] = {
    [TYPE_MATCH] = "matchreg",
};

static const char *get_data_directory()
{
    static char dir[PATH_MAX];

    // Check if the directory is already known
    if (*dir) return dir;

    // Not known, figure it out.
    if (readlink("/proc/self/exe", dir, sizeof dir) < 0) {
        warn("readlink() returned error, might be unable to find data files");
        // I dunno, just use cwd?
        return strcpy(dir, ".");
    }

    dbgmsg("full path of executable is %s", dir);

    // Now remove the filename
    dirname(dir);

    dbgmsg("therefore data directory is %s", dir);

    return dir;
}

// This will eventually enable looking up symbolic names in per-cpu json files.
uint64_t data_lookup_symbol(patch_t *patch, uint8_t type, const char *name)
{
    struct json_object *obj;
    struct json_object_iterator it;
    struct json_object_iterator end;
    uint32_t cpuid = patch->hdr.cpuid;
    char datafile[PATH_MAX] = {0};

    if (type >= TYPE_LAST) {
        errx(EXIT_FAILURE, "type %u is out of range", type);
    }

    // Figure out the name of the data file we want
    snprintf(datafile, sizeof datafile, "%s/data/cpu%04X_%s.json",
                                        get_data_directory(),
                                        cpuid,
                                        typenames[type]);

    dbgmsg("looking for datafile %s", datafile);

    if ((obj = json_object_from_file(datafile)) != NULL)
        goto jsonfound;

    dbgmsg("no data known for cpu %#x, checking for any similar cpu...", cpuid);

    snprintf(datafile, sizeof datafile, "%s/data/cpu%04X_%s.json",
                                        get_data_directory(),
                                        cpuid & 0xFFF0,
                                        typenames[type]);

    if ((obj = json_object_from_file(datafile)) != NULL)
        goto jsonfound;

    snprintf(datafile, sizeof datafile, "%s/data/cpu%04X_%s.json",
                                        get_data_directory(),
                                        cpuid & 0xFF00,
                                        typenames[type]);

    if ((obj = json_object_from_file(datafile)) != NULL)
        goto jsonfound;

    snprintf(datafile, sizeof datafile, "%s/data/cpu%04X_%s.json",
                                        get_data_directory(),
                                        cpuid & 0xF000,
                                        typenames[type]);

    if ((obj = json_object_from_file(datafile)) != NULL)
        goto jsonfound;

    err(EXIT_FAILURE, "sorry, data file not found - cannot resolve symbolic names");

    goto error;

  jsonfound:

    it = json_object_iter_begin(obj);
    end = json_object_iter_end(obj);

    while (!json_object_iter_equal(&it, &end)) {
        const char *value  = json_object_iter_peek_name(&it);
        const char *symbol = json_object_get_string(json_object_iter_peek_value(&it));
        dbgmsg("comparing %s with %s", symbol, name);
        if (strncasecmp(symbol, name, strlen(name)) == 0) {
            uint64_t result = strtoul(value, NULL, 16);

            dbgmsg("found @ %s=%s", symbol, value);

            json_object_put(obj);
            return result;
        }
        json_object_iter_next(&it);
    }

    json_object_put(obj);

error:
    errx(EXIT_FAILURE, "failed to find symbolic name %s", name);
    return 0;
}

char *data_lookup_name(patch_t *patch, uint8_t type, uint64_t num)
{
    struct json_object *obj;
    struct json_object_iterator it;
    struct json_object_iterator end;
    uint32_t cpuid = patch->hdr.cpuid;
    char datafile[PATH_MAX] = {0};

    if (type >= TYPE_LAST) {
        errx(EXIT_FAILURE, "type %u is out of range", type);
    }

    if (num == 0) {
        return NULL;
    }

    // Figure out the name of the data file we want
    snprintf(datafile, sizeof datafile, "%s/data/cpu%04X_%s.json",
                                        get_data_directory(),
                                        cpuid,
                                        typenames[type]);

    dbgmsg("looking for datafile %s", datafile);

    if ((obj = json_object_from_file(datafile)) != NULL)
        goto jsonfound;

    dbgmsg("no data known for cpu %#x, checking for any similar cpu...", cpuid);

    snprintf(datafile, sizeof datafile, "%s/data/cpu%04X_%s.json",
                                        get_data_directory(),
                                        cpuid & 0xFFF0,
                                        typenames[type]);

    if ((obj = json_object_from_file(datafile)) != NULL)
        goto jsonfound;

    snprintf(datafile, sizeof datafile, "%s/data/cpu%04X_%s.json",
                                        get_data_directory(),
                                        cpuid & 0xFF00,
                                        typenames[type]);

    if ((obj = json_object_from_file(datafile)) != NULL)
        goto jsonfound;

    snprintf(datafile, sizeof datafile, "%s/data/cpu%04X_%s.json",
                                        get_data_directory(),
                                        cpuid & 0xF000,
                                        typenames[type]);

    if ((obj = json_object_from_file(datafile)) != NULL)
        goto jsonfound;

    goto error;

  jsonfound:

    it = json_object_iter_begin(obj);
    end = json_object_iter_end(obj);

    while (!json_object_iter_equal(&it, &end)) {
        const char *value  = json_object_iter_peek_name(&it);
        const char *symbol = json_object_get_string(json_object_iter_peek_value(&it));
        uint64_t result = strtoul(value, NULL, 16);

        if (result == num) {
            char *match;
            // FIXME: Ignore these for now until I clean up the data files.
            if (strcmp(symbol, "complete") == 0
             || strcmp(symbol,   "failed") == 0
             || strcmp(symbol, "executed") == 0
             || strcmp(symbol,   "loaded") == 0
             || strcmp(symbol,  "queried") == 0
             || strcmp(symbol,  "updated") == 0
            ) {
                json_object_put(obj);
                return NULL;
            }
            match = strdup(symbol);
            dbgmsg("found @ %s=%s", symbol, value);
            json_object_put(obj);
            return match;
        }

        json_object_iter_next(&it);
    }

    json_object_put(obj);

error:
    dbgmsg("failed to find matching symbolic name for %#x", num);
    return NULL;
}
