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

#include <system_error>
#include <stdexcept>
#include <cstdarg>

#include <xdk/util/str.h>

/**
 * @defgroup util_classes Utility Classes
 * @brief Helper classes for various utilities.
 */

/**
 * @ingroup util_classes
 * @brief Custom exception class for ExpKit-specific errors.
 */
struct ExpKitError : public std::runtime_error {
    /**
     * @brief Constructs an ExpKitError with a single error message.
     * @param error_msg The error message.
     */
    template <typename... Args>
    ExpKitError(const char* error_msg): std::runtime_error(error_msg) {}

    /**
     * @brief Constructs an ExpKitError with a formatted error message.
     * @tparam Args The types of the arguments for the format string.
     * @param format The format string.
     * @param args The arguments for the format string.
     */
    template <typename... Args>
    ExpKitError(const char* format, const Args&... args): std::runtime_error(format_str(format, args...)) {}
};

/**
 * @ingroup util_classes
 * @brief Represents an error based on the current value of errno.
 */
struct errno_error: std::system_error {
    /**
     * @brief Constructs an errno_error with the current errno value.
     */
    errno_error();

    /**
     * @brief Constructs an errno_error with the current errno value and an additional message.
     * @param __what An additional message describing the error.
     */
    errno_error(const char* __what);
};