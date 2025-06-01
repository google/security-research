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

#ifndef __UTIL_H
#define __UTIL_H

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define reset_getopt() do { optind = 1; } while (false);


void logdbg(const char *prefix, const char *format, ...);
void logmsg(const char *format, ...);
void logerr(const char *format, ...);
void logstr(const char *format, ...);
void loghex(const void *data, size_t size);
void putmsg(const char *format, ...);
void puterr(const char *format, ...);
void putstr(const char *format, ...);
// Taken from https://stackoverflow.com/a/39667442
char** str_split(char* a_str, const char a_delim);

#define dbgmsg(fmt...) logdbg(__func__, fmt)

// https://x.com/suarezvictor/status/1477697986243272706
#define bitoffsetof(t, f) \
    ({ union { uint64_t raw; t typ; } u; u.raw = 0; ++u.typ.f; __builtin_ctzll(u.raw); })

#define bitsizeof(t, f) \
    ({ union { uint64_t raw; t typ; } u; u.raw = 0; --u.typ.f; 8 * sizeof(u.raw) - __builtin_clzll(u.raw) -__builtin_ctzll(u.raw); })

#endif
