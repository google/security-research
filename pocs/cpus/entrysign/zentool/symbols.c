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

#include <stdint.h>
#include <search.h>
#include <string.h>
#include <stdbool.h>

#include "util.h"
#include "symbols.h"

static int symbol_compare_name(const void *a, const void *b)
{
    const char *x = a;
    const symbol_t *y = b;
    return strcmp(x, y->name);
}

static int symbol_compare_value(const void *a, const void *b)
{
    const uint64_t *x = a;
    const symbol_t *y = b;
    return *x - y->value;
}

symbol_t * symbol_lookup_name(symtab_t *table, const char *name)
{
    return lfind(name,
                 table->symbols,
                 &table->count,
                 sizeof(symbol_t),
                 symbol_compare_name);
}

symbol_t * symbol_lookup_value(symtab_t *table, uintptr_t value)
{
    return lfind(&value,
                 table->symbols,
                 &table->count,
                 sizeof(symbol_t),
                 symbol_compare_value);
}

