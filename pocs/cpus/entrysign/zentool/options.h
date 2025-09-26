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

#ifndef __OPTIONS_H
#define __OPTIONS_H

#ifndef ZENTOOL_VERSION
# define ZENTOOL_VERSION "prerelease"
#endif

extern struct globalopts {
    int verbose;
    int quiet;
    int debug;
    char *infile;
    char *outfile;
} options;

struct subcmds {
    const char *name;
    int (*handler)(int argc, char **argv);
    const char *description;
};

int print_usage_generic(const char *name, const char *param, const struct option *opts, const char **help);

bool opt_num_inrange(const char *range, int num);
bool opt_num_parse_max(const char *value, uint64_t *result, uint64_t max);
bool opt_num_parse(const char *value, uint64_t *result);

int cmd_fixup_main(int argc, char **argv);
int cmd_help_main(int argc, char **argv);
int cmd_load_main(int argc, char **argv);
int cmd_dump_main(int argc, char **argv);
int cmd_edit_main(int argc, char **argv);
int cmd_verify_main(int argc, char **argv);
int cmd_crypt_main(int argc, char **argv);
int cmd_factor_main(int argc, char **argv);
int cmd_ver_main(int argc, char **argv);

#endif
