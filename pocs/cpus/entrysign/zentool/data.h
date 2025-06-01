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

#ifndef __DATA_H
#define __DATA_H

enum {
    TYPE_MATCH,
    TYPE_LAST,
};

uint64_t data_lookup_symbol(patch_t *patch, uint8_t type, const char *name);
char    *data_lookup_name(patch_t *patch, uint8_t type, uint64_t num);

#endif
