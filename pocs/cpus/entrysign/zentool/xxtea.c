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
#include <stddef.h>
#include <err.h>

#include "xxtea.h"

#define XXTEA_MX (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z)))
#define XXTEA_DELTA 0x9e3779b9

int xxtea_encrypt(void *data, size_t len, const uint32_t *key) {
    uint32_t *v = data;
    uint32_t  n = (len / sizeof(uint32_t)) - 1;
    uint32_t  z = v[n], y = v[0], p, q = 6 + 52 / (n + 1), sum = 0, e;

    if (n < 1) {
        warnx("xxtea data length was invalid");
        return -1;
    }

    if (len % sizeof(uint32_t)) {
        warnx("xxtea data length was not a multiple of uint32_t");
        return -1;
    }

    while (0 < q--) {
        sum += XXTEA_DELTA;
        e = sum >> 2 & 3;
        for (p = 0; p < n; p++) {
            y = v[p + 1];
            z = v[p] += XXTEA_MX;
        }
        y = v[0];
        z = v[n] += XXTEA_MX;
    }

    return 0;
}

int xxtea_decrypt(void *data, size_t len, const uint32_t *key) {
    uint32_t *v = data;
    uint32_t  n = (len / sizeof(uint32_t)) - 1;
    uint32_t  z = v[n], y = v[0], p, q = 6 + 52 / (n + 1), sum = q * XXTEA_DELTA, e;

    if (n < 1) {
        warnx("xxtea data length was invalid");
        return -1;
    }

    if (len % sizeof(uint32_t)) {
        warnx("xxtea data length was not a multiple of uint32_t");
        return -1;
    }

    while (sum != 0) {
        e = sum >> 2 & 3;
        for (p = n; p > 0; p--) {
            z = v[p - 1];
            y = v[p] -= XXTEA_MX;
        }
        z = v[n];
        y = v[0] -= XXTEA_MX;
        sum -= XXTEA_DELTA;
    }

    return 0;
}
