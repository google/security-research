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

#ifndef __CRYPT_H
#define __CRYPT_H

int dump_patch_sig(const patch_t *patch);
int fixup_patch_hash(patch_t *patch, int offset);

static const uint32_t kDefaultExponent = 0x10001;

static const uint8_t kCMACKey[] = {
   0x2b, 0x7e, 0x15, 0x16,
   0x28, 0xae, 0xd2, 0xa6,
   0xab, 0xf7, 0x15, 0x88,
   0x09, 0xcf, 0x4f, 0x3c,
};

#endif
