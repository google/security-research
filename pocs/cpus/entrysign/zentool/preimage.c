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

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <getopt.h>
#include <err.h>
#include <openssl/cmac.h>
#include <openssl/aes.h>
#include <gmp.h>
#include <assert.h>

#include "ucode.h"
#include "risc86.h"
#include "util.h"
#include "crypt.h"
#include "options.h"
#include "factor.h"

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

static size_t get_data_size(patch_t *patch)
{
    return sizeof(patch->hdr) - offsetof(struct ucodehdr, options)
         + sizeof(*patch->matchregs) * patch->nmatch
         + sizeof(*patch->insns) * patch->nquad;
}

static uint8_t * get_data_linear(patch_t *patch)
{
    uint8_t *buf = malloc(get_data_size(patch));
    uint8_t *ptr = buf;

    if (buf == NULL) {
        errx(EXIT_FAILURE, "memory allocation failure");
    }

    ptr = mempcpy(ptr, &patch->hdr.options, sizeof(patch->hdr) - offsetof(struct ucodehdr, options));
    ptr = mempcpy(ptr, patch->matchregs, sizeof(*patch->matchregs) * patch->nmatch);
    ptr = mempcpy(ptr, patch->insns, sizeof(*patch->insns) * patch->nquad);
    return buf;
}

int dump_patch_sig(const patch_t *patch)
{
    uint8_t hash[16];   // actual hash
    int result;

    crypt_signed_hash(hash, patch->hdr.modulus, patch->hdr.signature, sizeof(patch->hdr.modulus));

    // compare actual hash to stored hash
    if (memcmp(hash, patch->hash, ARRAY_SIZE(patch->hash)) == 0) {
        logmsg("GOOD");
        result = 0;
    } else {
        logmsg("BAD");
        result = 1;
    }

    if (options.verbose) {
        logmsg("Expected: ");
        loghex(patch->hash, sizeof patch->hash);
    }

    return result;
}

static const uint8_t mul = 0x87;
static const uint8_t bs = 16;
static const uint8_t pad = 0x80;

static void mulbyx(uint8_t block[16])
{
    int v  = block[0] >> 7;
    for (int i = 0; i < bs - 1; i++) {
        block[i] = block[i] << 1 | block[i+1] >> 7;
    }
    block[bs-1] = (block[bs-1] << 1) ^ (v ? mul : 0);
}

int fixup_patch_hash(patch_t *patch, int offset)
{
    CMAC_CTX *ctx = CMAC_CTX_new();
    uint8_t result[16] = {0};
    uint8_t zero[16] = {0};
    uint8_t subkey1[16] = {0};
    uint8_t subkey2[16] = {0};
    ssize_t sacrificeIndex = offset;

    if (sacrificeIndex % bs) {
        errx(EXIT_FAILURE, "cant patch at a non-block offset, add %ld", bs - (sacrificeIndex % bs));
    }

    ssize_t preimagesz = get_data_size(patch);
    uint8_t *preimage  = get_data_linear(patch);
    uint8_t target[16];

    crypt_signed_hash(target, patch->hdr.modulus, patch->hdr.signature, sizeof(patch->hdr.modulus));

    AES_KEY wctx = {0};
    AES_set_encrypt_key((void *) kCMACKey, sizeof(kCMACKey) * CHAR_BIT, &wctx);
    AES_encrypt(zero, subkey1, &wctx);

    mulbyx(subkey1);
    memcpy(subkey2, subkey1, sizeof(subkey2));
    mulbyx(subkey2);

    ssize_t paddedInputSize = ((preimagesz + bs - 1) / bs) * bs;
    uint8_t *paddedInput = calloc(paddedInputSize, 1);

    if (paddedInput == NULL)
        err(EXIT_FAILURE, "memory allocation failure");

    memcpy(paddedInput, preimage, preimagesz);

    if ((preimagesz % bs) == 0) {
        for (int j = 0; j < bs; j++) {
            paddedInput[paddedInputSize-bs+j] ^= subkey1[j];
        }
    } else {
        paddedInput[preimagesz] = pad;
        for (int j = 0; j < bs; j++) {
            paddedInput[paddedInputSize-bs+j] ^= subkey2[j];
        }
    }

    for (int j = sacrificeIndex; j < sacrificeIndex + bs; j++) {
        paddedInput[j] = 0;
    }

    uint8_t *input = calloc(bs, 1);
    uint8_t *outForward = calloc(bs, 1);

    if (input == NULL || outForward == NULL)
        err(EXIT_FAILURE, "memory allocation failure");

    AES_set_encrypt_key((void *) kCMACKey, sizeof(kCMACKey) * CHAR_BIT, &wctx);

    for (int i = 0; i < sacrificeIndex / bs; i++) {
        for (int j = 0; j < bs; j++) {
            input[j] = outForward[j] ^ paddedInput[i*bs+j];
        }
        AES_encrypt(input, outForward, &wctx);
    }

    uint8_t *outBackward = calloc(bs, 1);

    memcpy(input, target, bs);
    AES_set_decrypt_key((void *) kCMACKey, sizeof(kCMACKey) * CHAR_BIT, &wctx);

    for (int i = (paddedInputSize/bs) - 1; i >= (sacrificeIndex / bs); i--) {
        AES_decrypt(input, outBackward, &wctx);
        for (int j = 0; j < bs; j++) {
            input[j] = outBackward[j] ^ paddedInput[i*bs+j];
        }
    }

    for (int j = 0; j < bs; j++) {
        paddedInput[sacrificeIndex+j] = outForward[j] ^ input[j];
    }

    if (preimagesz % bs == 0) {
        for (int j = 0; j < bs; j++) {
            paddedInput[paddedInputSize-bs+j] ^= subkey1[j];
        }
    } else {
        for (int j = 0; j < bs; j++) {
            paddedInput[paddedInputSize-bs+j] ^= subkey2[j];
        }
    }


    CMAC_Init(ctx, kCMACKey, sizeof kCMACKey, EVP_aes_128_cbc(), NULL);
    CMAC_Update(ctx, paddedInput, preimagesz);
    CMAC_Final(ctx, result, NULL);
    CMAC_CTX_free(ctx);

    if (memcmp(result, target, bs) != 0) {
        errx(EXIT_FAILURE, "oops, the preimage failed validation :(");
    }

    dbgmsg("preimage looks okay, installing compensation bytes");

    // Install the compensation bytes.
    offset -= sizeof(struct ucodehdr) - offsetof(struct ucodehdr, options);

    if (offset < 0) {
        errx(EXIT_FAILURE, "patch offset inside header is unlikely to work");
    }

    offset -= sizeof(match_t) * patch->nmatch;

    if (offset < 0) {
        errx(EXIT_FAILURE, "patch offset inside match registers might be rejected");
    }

    if ((size_t)(offset + bs) > sizeof(*patch->insns) * patch->nquad) {
        errx(EXIT_FAILURE, "patch offset out of range");
    }

    memcpy((uint8_t *)(patch->insns) + offset, paddedInput + sacrificeIndex, bs);

    free(input);
    free(outForward);
    free(outBackward);
    free(paddedInput);
    free(preimage);
    return 0;
}
