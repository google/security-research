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
#include <vector>
#include <xdk/pivot/StackPivot.h>
#include <xdk/payloads/Payload.h>

/**
 * @defgroup pivot_classes Pivot Classes
 * @brief Classes for stack pivoting and related techniques.
 */

/**
 * @ingroup pivot_classes
 * @brief Represents information about a single stack shifting gadget within a chain.
 */
struct StackShiftInfo {
    /// @brief The offset within the payload where the address of this stack shift pivot is written.
    uint64_t ret_offset;
    /// @brief The stack shift pivot gadget.
    const StackShiftPivot pivot;
};

/**
 * @ingroup pivot_classes
 * @brief Stores information about a chain of stack shifting gadgets.
 */
struct StackShiftingInfo {
    /// @brief A vector of individual stack shift gadget information.
    std::vector<StackShiftInfo> stack_shifts;
    /// @brief The starting offset within the payload where the first stack shift pivot address is written.
    uint64_t from_offset;
    uint64_t to_offset;
    uint64_t next_ret_offset;

    void Apply(uint64_t kaslr_base, Payload& payload);
};