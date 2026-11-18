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
#include <xdk/target/Target.h>

/**
 * @defgroup payloads_classes Payloads Classes
 * @brief Classes for generating and managing payloads.
 */

// Forward declarations for types used in the header if their full definitions
// are not strictly needed (e.g., if only pointers/references are used),
// but in this case, the full definitions are likely needed due to value types.
// struct RopAction; // Already fully defined below
// class Target; // Already fully defined below


/**
 * @ingroup payloads_classes
 * @brief Represents a single ROP (Return-Oriented Programming) action.
 *
 * A RopAction is a sequence of 64-bit values that form part of a ROP chain.
 * These values can represent addresses, immediate data, or arguments for gadgets.
 */
struct RopAction {
    /**
     * @brief The sequence of 64-bit values comprising this ROP action.
     */
    std::vector<uint64_t> values;
};

/**
 * @ingroup payloads_classes
 * @class RopChain
 * @brief Manages an ordered sequence of ROP actions to form a ROP chain.
 *
 * The RopChain class allows for the construction of complex ROP chains
 * by adding individual ROP actions or raw 64-bit values. It handles
 * KASLR (Kernel Address Space Layout Randomization) offsets and
 * argument substitution for actions defined by a Target.
 */
class RopChain {
public:
    /**
     * @brief Constructs a new RopChain.
     * @param target A reference to the Target object which provides definitions for ROP actions.
     * @param kaslr_base The base address for KASLR, used to adjust symbol addresses.
     */
    RopChain(Target &target, uint64_t kaslr_base);

    /**
     * @brief Adds a predefined ROP action to the chain.
     *
     * This method retrieves the sequence of ROP items for a given action ID
     * from the associated Target and constructs a RopAction, substituting
     * arguments and applying KASLR offsets where necessary.
     *
     * @param id The ID of the ROP action to add.
     * @param arguments A vector of 64-bit arguments to substitute into the action.
     * The index of an argument in this vector corresponds to its
     * `item.value` when `item.type == RopItemType::ARGUMENT`.
     * @throw ExpKitError If an unexpected RopAction item type is encountered or
     * if there are not enough arguments provided for an action.
     */
    void AddRopAction(RopActionId id, std::vector<uint64_t> arguments = {});

    /**
     * @brief Adds a raw 64-bit item directly to the ROP chain as a single-value action.
     *
     * This is useful for adding arbitrary values (e.g., stack pivots, return addresses,
     * or immediate values) that are not part of a predefined RopAction.
     *
     * @param item The 64-bit value to add.
     * @param offset If true, the `kaslr_base_` will be added to the item.
     * Defaults to false.
     */
    void Add(uint64_t item, bool offset = false);

    /**
     * @brief Retrieves the entire ROP chain as a vector of bytes.
     *
     * The 64-bit items in the chain are converted to a contiguous byte array.
     * This is useful for writing the ROP chain directly to memory or a file.
     *
     * @return A `std::vector<uint8_t>` representing the ROP chain in byte format.
     */
    std::vector<uint8_t> GetData() const;

    /**
     * @brief Retrieves the entire ROP chain as a vector of 64-bit words.
     *
     * This method collects all individual 64-bit values from the sequence of
     * RopActions into a single flat vector.
     *
     * @return A `std::vector<uint64_t>` representing the ROP chain as 64-bit words.
     */
    std::vector<uint64_t> GetDataWords() const;

    /**
     * @brief Calculates the total size of the ROP chain in bytes.
     * @return The total size of the ROP chain in bytes.
     */
    uint64_t GetByteSize() const;

    /**
     * @brief Retrieves the list of individual RopAction objects that compose this chain.
     * @return A `std::vector<RopAction>` containing all added ROP actions.
     */
    std::vector<RopAction> GetActions() const;

    /**
     * @brief The KASLR base address used for symbol offsetting.
     */
    uint64_t kaslr_base_;

    /**
     * @brief Stores the ordered sequence of ROP actions.
     */
    std::vector<RopAction> actions_;

private:
    /**
     * @brief A reference to the Target object, providing definitions for ROP actions.
     */
    Target& target_;
};