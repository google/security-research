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

#ifndef __SYMBOLS_H
#define __SYMBOLS_H

typedef struct {
    const char *name;
    uintptr_t    value;
} symbol_t;

typedef struct {
    uint64_t count;
    symbol_t *symbols;
} symtab_t;

symbol_t * symbol_lookup_name(symtab_t *table, const char *name);
symbol_t * symbol_lookup_value(symtab_t *table, uintptr_t value);
symbol_t * symbol_insert(symtab_t *table, const char *name, uintptr_t value);

bool symbol_remove_name(symtab_t *table, const char *name);
bool symbol_remove_value(symtab_t *table, uintptr_t value);
bool symbol_remove_name_value(symtab_t *table, const char *name, uintptr_t value);
bool symbol_remove(symtab_t *table, symbol_t *symbol);

symtab_t * symtab_create(void);
void       symtab_free(symtab_t *table);

#define DEFINE_SYMBOL(sym) { # sym, sym }

#endif

