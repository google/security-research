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

#include <stdint.h>

/**
 * @defgroup util_classes Utility Classes
 * @brief Helper classes for various utilities.
 */

/**
 * @ingroup util_classes
 * @brief Checks if the provided address is a valid KASLR base address.
 *
 * @param kbase_addr The address to check.
 * @return True if the address is a valid KASLR base, false otherwise.
 */
bool is_kaslr_base(uint64_t kbase_addr);

/**
 * @ingroup util_classes
 * @brief Checks if the provided address is a valid KASLR base address.
 *
 * @param kbase_addr The address to check.
 * @return The checked KASLR base address if valid.
 */
uint64_t check_kaslr_base(uint64_t kbase_addr);

/**
 * @ingroup util_classes
 * @brief Checks if the provided address is a valid kernel heap pointer.
 *
 * @param heap_leak The address to check.
 * @return The checked kernel heap pointer if valid.
 */
uint64_t check_heap_ptr(uint64_t heap_leak);