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

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

/**
 * @defgroup util_classes Utility Classes
 * @brief Helper classes for various utilities.
 */

/**
 * @ingroup util_classes
 * @class HexDump
 * @brief Utility class for generating hexadecimal dumps of memory.
 */
class HexDump {
public:
    /**
     * @brief Generates a hexadecimal dump of a memory buffer into a character array.
     * @param dst The destination character array to write the dump to.
     * @param buf The buffer containing the data to dump.
     * @param len The number of bytes to dump.
     * @note The dst buf needs to be large enough to store all the data. 16 bytes are converted into: "00 11 22 33 44 55 66 77  88 99 AA BB CC DD EE FF  |  0123456789ABCDEF\n" (70 bytes)
     */
static void Dump(char* dst, const uint8_t* buf, int len);

/**
 * @brief Generates a hexadecimal dump of a memory buffer into a string.
 * @param buf The buffer containing the data to dump.
 * @param len The number of bytes to dump.
 * @return A string containing the hexadecimal dump.
 */
static std::string Dump(const void* buf, int len);

/**
 * @brief Generates a hexadecimal dump of a vector of bytes into a string.
 * @param data The vector of bytes to dump.
 * @return A string containing the hexadecimal dump.
 */
static std::string Dump(const std::vector<uint8_t>& data);

/**
 * @brief Prints a hexadecimal dump of a memory buffer to the standard output.
 * @param buf The buffer containing the data to dump.
 * @param len The number of bytes to dump.
 */
static void Print(const void* buf, int len);

/**
 * @brief Prints a hexadecimal dump of a vector of bytes to the standard
 * output.
 * @param data The vector of bytes to dump.
 */
static void Print(const std::vector<uint8_t>& data);
};