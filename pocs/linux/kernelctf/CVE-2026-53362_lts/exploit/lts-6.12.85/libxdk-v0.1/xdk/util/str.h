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

#include <algorithm>
#include <cstdarg>
#include <string>
#include <vector>

/**
 * @defgroup util_classes Utility Classes
 * @brief Helper classes for various utilities.
 */

/**
 * @ingroup util_classes
 * @brief Formats a string using a format string and va_list arguments.
 * @param format The format string.
 * @param args The va_list containing the arguments.
 * @return The formatted string.
 */
std::string format_str(const char* format, va_list args);

/**
 * @ingroup util_classes
 * @brief Formats a string using a format string and a variadic number of arguments.
 * @tparam Args The types of the arguments.
 * @param format The format string.
 * @param args The arguments to format.
 */
template <typename... Args>
std::string format_str(const char* format, const Args&... args) {
    int buffer_size = std::snprintf(nullptr, 0, format, args...) + 1; // +1 for null terminator
    std::string result(buffer_size - 1, '\0');
    std::snprintf(result.data(), buffer_size, format, args...);
    return result;
}

/**
 * @ingroup util_classes
 * @brief Concatenates a vector of strings with a delimiter.
 * @param delimiter The string to use as a delimiter.
 * @param strings The vector of strings to concatenate.
 */
std::string str_concat(const std::string& delimiter, const std::vector<std::string>& strings);

/**
 * @ingroup util_classes
 * @brief Replaces all occurrences of a substring within a string.
 * @param str The string to perform replacements on.
 * @param from The substring to replace.
 * @param to The string to replace with.
 */
void replace(std::string& str, const std::string& from, const std::string& to);

/**
 * @ingroup util_classes
 * @brief Converts a string to lowercase in-place.
 * @param str The string to convert.
 */
void tolower(std::string& str);

/**
 * @ingroup util_classes
 * @brief Splits a string by a delimiter.
 * @param str The string to split.
 * @param delimiter The delimiter to split by.
 */
std::vector<std::string> split(const std::string& str, const std::string& delimiter);

/**
 * @ingroup util_classes
 * @brief Checks if a string contains a specific pattern.
 * @param str The string to search within.
 * @param pattern The pattern to search for.
 * @return True if the string contains the pattern, false otherwise.
 */
bool contains(const std::string& str, const std::string& pattern);

/**
 * @ingroup util_classes
 * @brief Checks if a string starts with a specific prefix.
 * @param str The string to check.
 * @param prefix The prefix to check for.
 * @return True if the string starts with the prefix, false otherwise.
 */
bool startsWith(const std::string& str, const std::string& prefix);