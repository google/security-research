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

/**
 * @file PayloadBuilder.h
 * @brief Defines the PayloadBuilder class for constructing complex exploit payloads.
 */
#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <optional>

// Project-specific includes
#include <xdk/pivot/Pivots.h>
#include <xdk/pivot/StackPivot.h>
#include <xdk/pivot/StackShiftInfo.h>
#include <xdk/payloads/RopChain.h>
#include <xdk/payloads/Payload.h>

/**
 * @defgroup payloads_classes Payloads Classes
 * @brief Classes for generating and managing payloads.
 */

/**
 * @ingroup payloads_classes
 * @brief Helper struct to encapsulate payload data for the builder.
 *
 * This struct groups a Payload object, associated registers, and an optional
 * offset for the next RIP (Instruction Pointer).
 *
 * @note The `registers` member is stored by value, meaning a copy is made.
 */
struct PayloadData {
    Payload& payload;                          ///< @brief Reference to the Payload object.
    const std::vector<Register> registers;     ///< @brief Registers pointing to this buffer when RIP control is triggered.
    const std::optional<size_t> rip_ptr_offset; ///< @brief Optional offset of a field containing a function pointer which if overwritten can lead to RIP control. If nullopt, then this payload does not contain such a field.

    /**
     * @brief Constructs a PayloadData instance.
     * @param payload_ref Reference to the Payload.
     * @param regs Optional vector of Registers pointing to this buffer when RIP control is triggered (defaults to empty).
     * @param rip_ptr_offset Optional offset of a field containing a function pointer which if overwritten can lead to RIP control. If nullopt, then this payload does not contain such a field.
     */
    PayloadData(Payload &payload_ref,
                const std::vector<Register> &regs = {},
                std::optional<size_t> rip_ptr_offset = std::nullopt)
        : payload(payload_ref), registers(regs), rip_ptr_offset(rip_ptr_offset)
    {
    }
};


/**
 * @ingroup payloads_classes
 * @brief Converts a 64-bit unsigned integer to its hexadecimal string representation.
 * @param value The 64-bit unsigned integer to convert.
 * @return A `std::string` containing the "0x" prefixed hexadecimal representation
 * of the value (uppercase).
 */
std::string intToHex(uint64_t value);


/**
 * @ingroup payloads_classes
 * @class PayloadBuilder
 * @brief A class designed to construct and optimize exploit payloads.
 *
 * This builder manages multiple payload components, ROP (Return-Oriented Programming)
 * chains, and stack pivots to create a cohesive and functional exploit payload.
 * It attempts to find suitable stack pivots and apply ROP actions efficiently.
 *
 * @details
 * The implementation tracks `StackShiftingInfo` for every `RopAction`. If two actions
 * can be stored adjacently, the `StackShiftingInfo` between them will represent an empty shift.
 */
class PayloadBuilder {
public:
    /**
     * @brief Constructs a PayloadBuilder instance.
     * @param pivots Available stack pivot gadgets.
     * @param kaslr_base The Kernel Address Space Layout Randomization base address.
     */
    PayloadBuilder(const Pivots &pivots, uint64_t kaslr_base) : pivots_(pivots), kaslr_base_(kaslr_base){}

    /**
     * @brief Adds a new payload component to the builder.
     * @param payload A reference to the Payload object to add.
     * @param registers Optional vector of Registers pointing to this buffer when RIP control is triggered (defaults to empty).
     * @param rip_ptr_offset Optional offset of a field containing a function pointer which if overwritten can lead to RIP control. If nullopt, then this payload does not contain such a field.
     */
    void AddPayload(Payload& payload,
                    const std::vector<Register>& registers = {},
                    std::optional<size_t> rip_ptr_offset = std::nullopt);

    /**
     * @brief Adds a new payload component with an optional single register.
     * @param payload A reference to the Payload object to add.
     * @param reg Optional register pointing to this buffer when RIP control is triggered (defaults to nullopt - so no register points to this buffer).
     * @param rip_ptr_offset Optional offset of a field containing a function pointer which if overwritten can lead to RIP control. If nullopt, then this payload does not contain such a field.
     */
    void AddPayload(Payload& payload,
                    std::optional<Register> reg = std::nullopt,
                    std::optional<size_t> rip_ptr_offset = std::nullopt);

    /**
     * @brief Appends a ROP chain to the builder's sequence of ROP actions.
     * @param rop_chain The RopChain object to add.
     */
    void AddRopChain(const RopChain& rop_chain);

    /**
     * @brief Uses stack shift gadgets to shift the stack by at least shift_value.
     *
     * This method is useful for moving the rop chain towards the end of the buffer.
     * This can prevent function calls from clobbering data before the buffer.
     *
     * @param shift_value Shifts the stack by at least shift_value.
     */
    void SetRopShift(const uint64_t shift_value);

    /**
     * @brief Attempts to build the final payload.
     *
     * This method tries to find a suitable stack pivot, applies it to the
     * payload, and then attempts to integrate all ROP actions, performing
     * stack shifts as necessary.
     *
     * @param need_pivot If true, the builder will explicitly look for a pivot (defaults to `true`).
     * @return `true` if a successful payload is built, `false` otherwise.
     * @throws ExpKitError if multiple RIP offsets are found when `need_pivot` is true.
     */
    bool Build(bool need_pivot = true);

    /**
     * @brief Prints debug information about the built payload, if successful.
     *
     * This includes details about the chosen stack pivot, stack shifts, and ROP chain layout.
     */
    void PrintDebugInfo() const;

    /**
     * @brief Returns the chosen stack pivot
     *
     * This function may be called after Build() to get the stack pivot gadget that was chosen.
     */
    StackPivot GetStackPivot();

private:
    /**
     * @brief Attempts to apply a given stack pivot to a payload and integrate ROP actions.
     * @param payload A reference to the Payload object to modify.
     * @param pivot The StackPivot to try.
     * @return `true` if the pivot and all ROP actions can be successfully applied, `false` otherwise.
     */
    bool TryPayloadPivot(Payload& payload, StackPivot pivot);

    /**
     * @brief Estimates the contiguous free space after a given offset in a payload.
     *
     * This helper function is used during the build process to evaluate potential
     * payload layouts. It assumes 8-byte (uint64_t) alignment for free space.
     *
     * @param payload A reference to the Payload object.
     * @param offset The starting offset from which to estimate free space.
     * @return The estimated available free space in bytes.
     */
    uint64_t EstimatePayloadSpaceAfter(Payload& payload, uint64_t offset);

    std::vector<PayloadData> payload_datas_;              ///< @brief List of payload components to integrate.
    std::vector<RopAction> rop_actions_;                  ///< @brief Sequence of ROP actions to execute.
    uint64_t rop_shift_ = 0;                              ///< @brief Minimum shift before the rop payload inserted
    Pivots pivots_;                                       ///< @brief Available stack pivot gadgets.
    uint64_t kaslr_base_;                                 ///< @brief The Kernel Address Space Layout Randomization base address.
    std::optional<StackPivot> chosen_pivot_;              ///< @brief The pivot chosen during the build process.
    std::optional<Payload> chosen_payload_;               ///< @brief The final constructed payload.
    std::vector<StackShiftingInfo> chosen_shifts_;        ///< @brief Information about stack shifts performed during the build.
};