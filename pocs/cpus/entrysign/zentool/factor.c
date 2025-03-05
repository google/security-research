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
#include <errno.h>

#include "ucode.h"
#include "risc86.h"
#include "util.h"
#include "crypt.h"
#include "options.h"
#include "primes.h"
#include "factor.h"

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

static const struct option kLongOpts[] = {
    {          "help", false, NULL, 'h' },
    {0},
};

static const char *kOptHelp[] = {
    "print this message",
};

static const uint8_t mul    = 0x87;
static const uint8_t bs     = 16;   // blocksize
static const uint8_t pad    = 0x80;

// Calculate the modulus check field used in a microcode patch, I don't know
// the purpose of this field, but we figured out how to calculate it.
bool crypt_calc_check(uint8_t *check, const uint8_t *modulus, size_t nbytes)
{
    mpz_t c, n, e;
    dbgmsg("finding check value of %u byte modulus", nbytes);
    mpz_inits(c, n, e, NULL);
    mpz_import(n, nbytes, 1, 1, 0, 0, modulus);
    mpz_ui_pow_ui(e, 2, 2048);
    mpz_invert(c, n, e);
    mpz_sub_ui(e, e, 1);
    mpz_mul(c, c, e);
    mpz_ui_pow_ui(e, 2, 2048);
    mpz_mod(c, c, e);
    mpz_export(check, NULL, -1, nbytes, 1, 0, c);
    mpz_clears(c, n, e, NULL);
    if (options.debug) {
        dbgmsg("calculation complete, result:");
        loghex(check, nbytes);
    }
    return true;
}

bool crypt_hash_bytes(uint8_t hash[16], const void *buffer, size_t nbytes)
{
    CMAC_CTX *ctx = CMAC_CTX_new();

    dbgmsg("hashing %u bytes of data", nbytes);

    CMAC_Init(ctx, kCMACKey, sizeof kCMACKey, EVP_aes_128_cbc(), NULL);
    CMAC_Update(ctx, buffer, nbytes);
    CMAC_Final(ctx, hash, NULL);

    if (options.debug) {
        dbgmsg("hashing complete, result:");
        loghex(hash, 16);
    }

    CMAC_CTX_free(ctx);
    return true;
}

bool crypt_calc_modhash(uint8_t hash[16], const uint8_t *modulus, size_t nbytes)
{
    dbgmsg("hashing %u byte modulus", nbytes);
    return crypt_hash_bytes(hash, modulus, nbytes);
    return true;
}

bool crypt_signed_hash(uint8_t hash[16], const uint8_t *modulus, const uint8_t *signature, size_t nbytes)
{
    uint8_t *buf;
    mpz_t s, n, h;

    dbgmsg("finding signed hash value, %d byte signature", nbytes);

    mpz_inits(s, n, h, NULL);
    mpz_import(s, nbytes, 1, 1, 0, 0, signature);
    mpz_import(n, nbytes, 1, 1, 0, 0, modulus);

    mpz_powm_ui(h, s, kDefaultExponent, n);

    // Extract the last few bytes, then read them back in.
    buf = mpz_export(NULL, NULL, -1, 16, 1, 0, h);
    mpz_import(h, 16, 1, 1, 0, 0, buf);

    if (options.debug) {
        gmp_printf("found signed hash %Zx\n", h);
    }

    memcpy(hash, buf, 16);
    mpz_clears(s, n, h, NULL);
    free(buf);
    return true;
}

bool crypt_patch_hash(uint8_t hash[16], const patch_t *patch)
{
    CMAC_CTX *ctx = CMAC_CTX_new();
    dbgmsg("hashing entire patch to %p", hash);
    CMAC_Init(ctx, kCMACKey, sizeof kCMACKey, EVP_aes_128_cbc(), NULL);
    CMAC_Update(ctx, &patch->hdr.options, sizeof(patch->hdr) - offsetof(struct ucodehdr, options));
    CMAC_Update(ctx, patch->matchregs, sizeof(*patch->matchregs) * patch->nmatch);
    CMAC_Update(ctx, patch->insns, sizeof(*patch->insns) * patch->nquad);
    CMAC_Final(ctx, hash, NULL);
    CMAC_CTX_free(ctx);
    return 0;
}

static void mulbyx(uint8_t block[16])
{
    int v  = block[0] >> 7;
    for (int i = 0; i < bs - 1; i++) {
        block[i] = block[i] << 1 | block[i+1] >> 7;
    }
    block[bs-1] = (block[bs-1] << 1) ^ (v ? mul : 0);
}

static bool crypt_find_preimage(uint8_t target[16], uint8_t *preimage, size_t preimagesz, size_t sacrificeIndex)
{
    uint8_t result[16] = {0};
    uint8_t zero[16] = {0};
    uint8_t subkey1[16] = {0};
    uint8_t subkey2[16] = {0};

    if (sacrificeIndex % bs) {
        errx(EXIT_FAILURE, "cant patch at a non-block offset, add %ld", bs - (sacrificeIndex % bs));
    }

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

    for (size_t j = sacrificeIndex; j < sacrificeIndex + bs; j++) {
        paddedInput[j] = 0;
    }

    uint8_t *input = calloc(bs, 1);
    uint8_t *outForward = calloc(bs, 1);

    if (input == NULL || outForward == NULL)
        err(EXIT_FAILURE, "memory allocation failure");

    AES_set_encrypt_key((void *) kCMACKey, sizeof(kCMACKey) * CHAR_BIT, &wctx);

    for (size_t i = 0; i < sacrificeIndex / bs; i++) {
        for (int j = 0; j < bs; j++) {
            input[j] = outForward[j] ^ paddedInput[i*bs+j];
        }
        AES_encrypt(input, outForward, &wctx);
    }

    uint8_t *outBackward = calloc(bs, 1);

    memcpy(input, target, bs);
    AES_set_decrypt_key((void *) kCMACKey, sizeof(kCMACKey) * CHAR_BIT, &wctx);

    for (size_t i = (paddedInputSize/bs) - 1; i >= (sacrificeIndex / bs); i--) {
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

    crypt_hash_bytes(result, paddedInput, preimagesz);

    if (memcmp(result, target, bs) != 0) {
        errx(EXIT_FAILURE, "oops, the preimage failed validation :(");
    }

    dbgmsg("preimage looks okay, installing %d compensation bytes at offset %d", bs, sacrificeIndex);

    // Install the compensation bytes.
    memcpy(preimage + sacrificeIndex, paddedInput + sacrificeIndex, bs);

    free(input);
    free(outForward);
    free(outBackward);
    free(paddedInput);
    return 0;
}

static bool factor_produce_key(int bits, uint8_t target[16], uint8_t *modulus, uint8_t *private)
{
    uint8_t *key = calloc(1, bits / 8);
    mpz_t d, exp, p, n, left, mod, toitent;

    if (bits % 8) {
        errx(EXIT_FAILURE, "bits must be a multiple of 8");
    }

    if (bits < 512) {
        errx(EXIT_FAILURE, "just factor the key by hand");
    }

    if (key == NULL) {
        errx(EXIT_FAILURE, "memory allocation failure");
    }

    key[0]  = 0x80;
    key[bits / 8 - 1] = 0x01;

    mpz_inits(d, exp, n, p, left, mod, toitent, NULL);

    for (int i = 0; i < 5 * bits; i++) {
        crypt_find_preimage(target, key, bits / 8, 16);

        mpz_import(n, bits / 8, 1, 1, 0, 0, key);
        mpz_set(left, n);
        mpz_set_ui(toitent, 1);
        mpz_set_ui(exp, kDefaultExponent);

        for (int j = 0; kPrimes[j]; j++) {
            bool first = true;
            mpz_set_ui(p, kPrimes[j]);
            while (mpz_mod_ui(mod, left, kPrimes[j]) == 0) {
                if (first) {
                    first = false;
                    mpz_mul_ui(toitent, toitent, kPrimes[j] - 1);
                } else {
                    mpz_mul_ui(toitent, toitent, kPrimes[j]);
                }
                assert(mpz_divisible_ui_p(left, kPrimes[j]));
                mpz_divexact_ui(left, left, kPrimes[j]);
            }
        }

        if (mpz_probab_prime_p(left, 10)) {
            mpz_sub_ui(left, left, 1);
            mpz_mul(toitent, toitent, left);
            if (mpz_mod_ui(mod, toitent, mpz_get_ui(exp)) != 0) {
                mpz_invert(d, exp, toitent);
                if (options.debug) {
                    gmp_printf("    D: %Zx\n", d);
                    gmp_printf("    N: %Zx\n", n);
                }
                assert(mpz_sizeinbase(n, 2) <= (size_t) bits);
                assert(mpz_sizeinbase(d, 2) <= (size_t) bits);
                mpz_export(modulus, NULL, -1, bits / 8, 1, 0, n);
                mpz_export(private, NULL, -1, bits / 8, 1, 0, d);
                goto complete;
            }
        }

        for (int k = bits / 8 - 1; k >= 0; k--) {
            key[k]++;
            if (key[k] != 0) {
                break;
            }
        }
        key[bits/8-1]++;
    }

    errx(EXIT_FAILURE, "failed to find acceptable key");

  complete:
    free(key);
    mpz_clears(d, n, exp, p, left, mod, toitent, NULL);
    return true;
}

int crypt_resign_patch(patch_t *patch, uint8_t *modulus, uint8_t *private)
{
    size_t bits = sizeof(patch->hdr.modulus) * CHAR_BIT;
    uint8_t *padded = calloc(bits / 8, 1);
    mpz_t s, d, n, c, h, e;

    mpz_inits(s, d, n, c, h, e, NULL);

    if (options.debug) {
        dbgmsg("hash of signed data");
        loghex(patch->hash, sizeof(patch->hash));
    }

    if (padded == NULL) {
        errx(EXIT_FAILURE, "memory allocation failure");
    }

    padded[0] = 0x00;
    padded[1] = 0x01;
    padded[2] = 0x00;

    for (size_t i = 2; i < bits / 8 - sizeof(patch->hash) - 1; i++) {
        padded[i] = 0xff;
    }

    padded[bits / 8 - sizeof(patch->hash) - 1] = 0x00;

    for (size_t i = 0; i < sizeof(patch->hash); i++) {
        padded[bits / 8 - sizeof(patch->hash) + i] = patch->hash[i];
    }

    if (options.debug) {
        logmsg("signing this padded hash...");
        loghex(padded, bits / 8);
    }

    mpz_import(s, sizeof(patch->hdr.modulus), 1, 1, 0, 0, padded);
    mpz_import(d, sizeof(patch->hdr.modulus), 1, 1, 0, 0, private);
    mpz_import(n, sizeof(patch->hdr.modulus), 1, 1, 0, 0, modulus);

    mpz_powm(s, s, d, n);

    mpz_export(patch->hdr.modulus, NULL, -1, bits / 8, 1, 0, n);
    mpz_export(patch->hdr.signature, NULL, -1, bits / 8, 1, 0, s);
    crypt_calc_check(patch->hdr.check, patch->hdr.modulus, bits / 8);

    if (options.debug) {
        gmp_printf("Signature: %ZX\n", s);
    }

    mpz_clears(s, d, n, c, h, e, NULL);

    free(padded);
    return 0;
}


int crypt_factor_patch(patch_t *patch)
{
    uint8_t target[16] = {0};
    uint8_t modulus[256] = {0};
    uint8_t private[256] = {0};

    // We need our own key where cmac(modulus) == cmac(patch->hdr.modulus)
    crypt_calc_modhash(target, patch->hdr.modulus, sizeof(patch->hdr.modulus));

    if (options.debug) {
        dbgmsg("Desired Hash:");
        loghex(target, 16);
    }

    factor_produce_key(sizeof(patch->hdr.signature) * CHAR_BIT, target, modulus, private);

    crypt_calc_modhash(target, modulus, sizeof(patch->hdr.modulus));

    if (options.debug) {
        dbgmsg("Received Hash:");
        loghex(target, 16);
    }

    crypt_resign_patch(patch, modulus, private);

    return 0;
}

static int print_usage(const char *name)
{
    return print_usage_generic(name, "FILE...", kLongOpts, kOptHelp);
}

int cmd_factor_main(int argc, char **argv)
{
    patch_t *patch;
    int longopt;
    int c;

    reset_getopt();

    while ((c = getopt_long(argc, argv, "h", kLongOpts, &longopt)) != -1) {
        switch (c) {
            case 'h': print_usage(*argv);
                      return 0;
            case '?': print_usage(*argv);
                      errx(EXIT_FAILURE, "invalid options");
        }
    }

    if (optind == argc) {
        print_usage(*argv);
        errx(EXIT_FAILURE, "must provide at least a filename");
    }

    patch = load_patch_file(argv[optind]);

    if (patch == NULL) {
        errx(EXIT_FAILURE, "failed to parse file %s", argv[optind]);
    }

    crypt_factor_patch(patch);
    save_patch_file(patch, argv[optind]);

    free_patch_file(patch);
    return 0;
}
