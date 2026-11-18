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

 #pragma once
 #include <vector>

 /**
 * @brief Includes a binary file into the executable.
 * @param var_name The name for the included data and size variables.
 * @param filename The path to the binary file to include.
 */
#define INCBIN(var_name, filename) \
    __asm__(".section .rodata\n" \
            #var_name "_begin:\n" \
            ".incbin \"" filename "\"\n" \
            #var_name "_end:\n" \
    ); \
    extern const unsigned char var_name ## _begin[]; \
    extern const unsigned char var_name ## _end[]; \
    __asm__(".section .bss\n"); \
    extern const size_t var_name ## _size = var_name ## _end - var_name ## _begin; \
    std::vector<uint8_t> var_name = std::vector<uint8_t>(var_name ## _begin, var_name ## _end);
