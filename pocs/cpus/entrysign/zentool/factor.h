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

#ifndef __FACTOR_H
#define __FACTOR_H
bool crypt_calc_check(uint8_t *check, const uint8_t *modulus, size_t nbytes);
bool crypt_hash_bytes(uint8_t hash[16], const void *buffer, size_t nbytes);
bool crypt_calc_modhash(uint8_t hash[16], const uint8_t *modulus, size_t nbytes);
bool crypt_signed_hash(uint8_t hash[16], const uint8_t *modulus, const uint8_t *signature, size_t nbytes);
bool crypt_patch_hash(uint8_t hash[16], const patch_t *patch);

#endif
