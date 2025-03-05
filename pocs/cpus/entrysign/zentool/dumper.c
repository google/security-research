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
#include <stdio.h>
#include <stdlib.h>

//5:0 = 50033

int
main(int argc, char **argv)
{
    if (argc < 2 || argc > 4) {
        printf("Usage: %s offset [length] [output]\n", argv[0]);
        return 1;
    }
    uint64_t offset;
    uint64_t output;
    uint64_t length;
    uint64_t addr;
    FILE *fp = NULL;
    uint64_t *buffer = NULL;
    offset = strtoul(argv[1], NULL, 16);
    length = 8;
    if (argc >= 3) {
        length = strtoul(argv[2], NULL, 16);
        buffer = (uint64_t *)calloc(length, 1);
    }
    if (argc == 4) {
        fp = fopen(argv[3], "w");
        printf("Writing output to %s, omitting prints.\n", argv[3]);
    }
    for (uint64_t i = 0; i < length; i += 8) {
        output = 0;
        addr = offset + i;
        asm volatile(
            "mov %[input], %%rsi\n"
            "fpatan\n"
            "mov %%rdi, %[output]"
            : [output]"=g"(output)
            : [input]"g"(addr)
            : "rdi", "rax"
        );
        if (!fp) {
            printf("[0x%016lx] %016lX\n", addr, output);
        }
        if (buffer) {
            buffer[i/8] = output;
        }
    }
    if (fp) {
        fwrite(buffer, 1, length, fp);
        fclose(fp);
        fp = NULL;
    }
    if (buffer) {
        free(buffer);
    }
    return 0;
}