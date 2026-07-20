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

#include <optional>
#include <string>
#include <xdk/pivot/Pivots.h>
#include <xdk/payloads/Payload.h>

/**
 * @defgroup pivot_classes Pivot Classes
 * @brief Classes for stack pivoting and related techniques.
 */

/**
 * @ingroup pivot_classes
 * @brief Represents a potential stack pivot gadget or sequence of gadgets.
 *
 * This class encapsulates information about different types of stack pivots (one-gadget, push/pop) and provides methods to apply them to a payload.
 */
class StackPivot {
    std::optional<OneGadgetPivot> one_gadget_;
    std::optional<PushIndirectPivot> push_gadget_;
    std::optional<PopRspPivot> pop_gadget_;
public:
    /**
     * @brief Constructs a StackPivot from a OneGadgetPivot.
     * @param one_gadget The OneGadgetPivot to use.
     */
StackPivot(const OneGadgetPivot& one_gadget);

/**
 * @brief Constructs a StackPivot from a PushIndirectPivot and a PopRspPivot.
 * @param push_gadget The PushIndirectPivot to use.
 * @param pop_gadget The PopRspPivot to use.
 */
StackPivot(const PushIndirectPivot& push_gadget, const PopRspPivot& pop_gadget);

/**
 * @brief Gets a string description of the stack pivot.
 * @param include_clobbers Whether to include information about clobbered
 * offsets in the description.
 * @return A string describing the stack pivot.
 * @throws ExpKitError if the StackPivot is in an invalid state.
 */
std::string GetDescription(bool include_clobbers = true) const;

/**
 * @brief Gets the address of the primary gadget in the stack pivot.
 * @return The address of the primary gadget.
 */
uint64_t GetGadgetOffset();

/**
 * @brief Gets the destination offset within the buffer where the pivot will
 * transfer execution.
 * @return The destination offset.
 *
 * This is typically the location where the next instruction or ROP chain
 * should be placed.
 */
uint64_t GetDestinationOffset() const;

/**
 * @brief Applies the stack pivot to a given payload.
 * @param payload The Payload object to modify.
 * @param kaslr_base The KASLR base address.
 */
void ApplyToPayload(Payload& payload, uint64_t kaslr_base);
};