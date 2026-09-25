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

#include <set>
#include <limits>
#include <optional>
#include <xdk/pivot/Pivots.h>
#include <xdk/pivot/StackPivot.h>
#include <xdk/pivot/StackShiftInfo.h>
#include <xdk/payloads/Payload.h>
#include <xdk/payloads/RopChain.h>

/**
 * @defgroup pivot_classes Pivot Classes
 * @brief Classes for stack pivoting and related techniques.
 */

/**
 * @ingroup pivot_classes
 * @brief Encapsulates information about a successful ROP pivot.
 */
struct RopPivotInfo {
    /** @brief The ROP chain being pivoted to. */
    const RopChain& rop;
    /** @brief The chosen stack pivot gadget. */
    StackPivot pivot;
    /** @brief The minimum required offset for the ROP chain after shifting. */
    uint64_t rop_min_offset;
    /** @brief The actual offset within the payload where the ROP chain is placed. */
    uint64_t rop_offset;
    /** @brief Information about the stack shifting performed. */
    StackShiftingInfo stack_shift;

    /**
     * @brief Prints debug information about the ROP pivot.
     *
     * This includes details about the selected stack pivot, stack shifts, and ROP chain offset.
     */
    // TODO: make this more universal
    void PrintDebugInfo() const;
};

/**
 * @ingroup pivot_classes
 * @class PivotFinder
 * @brief Finds suitable stack pivots and stack shifting gadgets within a payload.
 */
class PivotFinder {
    Pivots pivots_;
    std::set<Register> buf_regs_;
    Payload& payload_;

    /**
     * @brief Internal helper function to find stack pivot gadgets.
     *
     * This function searches for both one-gadget and push/indirect/pop RSP
     * style pivots that are compatible with the current payload state and buffer registers.
     *
     * @param only_one If true, stops after finding the first suitable pivot.
     * @param free_bytes_after The minimum number of free bytes required after the pivot's next RIP offset.
     * @return A vector of found StackPivot objects.
     */
    std::vector<StackPivot> FindInternal(bool only_one,
                                         uint64_t free_bytes_after = 0);

    /**
     * @brief Sorts the internal lists of pivot gadgets by their next RIP offset or shift amount.
     *
     * Sorting helps in finding the most suitable gadgets efficiently.
     */
    void SortFields();

public:
    /**
     * @brief Constructs a PivotFinder object with a single buffer register.
     *
     * @param pivots The collection of available pivot gadgets.
     * @param buf_reg The single register pointing to the target buffer.
     * @param payload The payload object to operate on.
     */
    PivotFinder(const Pivots& pivots, Register buf_reg, Payload& payload);

    /**
     * @brief Constructs a PivotFinder object with multiple buffer registers.
     *
     * @param pivots The collection of available pivot gadgets.
     * @param buf_regs A vector of registers pointing to the target buffer.
     * @param payload The payload object to operate on.
     */
    PivotFinder(const Pivots& pivots, std::vector<Register> buf_regs,
                Payload& payload);

    /**
     * @brief Checks if a given register usage is compatible with the buffer registers
     * and doesn't overlap with reserved space in the payload.
     *
     * @param reg The RegisterUsage to check.
     * @return True if the register usage is valid for pivoting, false otherwise.
     * @note This function has TODOs related to more advanced checks for RIP control and skipping used space.
     */
    bool CheckRegister(const RegisterUsage& reg);

    /**
     * @brief Checks if a One-Gadget pivot is valid for the current payload state.
     *
     * @param pivot The OneGadgetPivot to check.
     * @param free_bytes_after The minimum number of free bytes required after the pivot's next RIP offset.
     * @return True if the One-Gadget pivot is valid, false otherwise.
     */
    bool CheckOneGadget(const OneGadgetPivot& pivot,
                        uint64_t free_bytes_after = 0);

    /**
     * @brief Checks if a Push/Indirect pivot is valid for the current payload state.
     *
     * @param pivot The PushIndirectPivot to check.
     * @param free_bytes_after The minimum number of free bytes required after the pivot's next RIP offset.
     * @return True if the Push/Indirect pivot is valid, false otherwise.
     */
    bool CheckPushIndirect(const PushIndirectPivot& pivot,
                            uint64_t free_bytes_after = 0);

    /**
     * @brief Finds all suitable stack pivot gadgets.
     *
     * @return A vector containing all found StackPivot objects.
     */
    std::vector<StackPivot> FindAll();

    /**
     * @brief Finds a stack shift gadget with a shift amount greater than or equal
     * to `min_shift` and less than `upper_bound`.
     *
     * @param min_shift The minimum required stack shift amount.
     * @param upper_bound The exclusive upper bound for the stack shift amount.
     * @return An optional StackShiftPivot if a suitable gadget is found, otherwise `std::nullopt`.
     */
    std::optional<StackShiftPivot> FindShift(
        uint64_t min_shift,
        uint64_t upper_bound = std::numeric_limits<uint64_t>::max());

    /**
     * @brief Finds a single suitable stack pivot gadget.
     *
     * @param free_bytes_after The minimum number of free bytes required after the pivot's next RIP offset.
     * @return An optional StackPivot object. Contains a value if a pivot is found, otherwise `std::nullopt`.
     */
    std::optional<StackPivot> Find(uint64_t free_bytes_after = 0);

    /**
     * @brief Finds a sequence of stack shift gadgets to shift the stack pointer
     * from a given offset to at least a minimum target offset.
     *
     * @param from_offset The starting offset of the stack pointer.
     * @param min_to_offset The minimum desired offset for the stack pointer.
     * @return An optional StackShiftingInfo object. Contains a value if a sequence of shifts is found, otherwise `std::nullopt`.
     */
    std::optional<StackShiftingInfo> GetShiftToOffset(uint64_t from_offset,
                                                     uint64_t min_to_offset);

    /**
     * @brief Finds a sequence of stack shift gadgets to shift the stack pointer
     * to accommodate a ROP chain of a given size.
     *
     * @param from_offset The starting offset of the stack pointer.
     * @param byte_size The size of the ROP chain in bytes.
     * @param include_extra_slot If true, includes an extra 8 bytes in the required space.
     * @return An optional StackShiftingInfo object. Contains a value if a sequence of shifts is found, otherwise `std::nullopt`.
     */
    std::optional<StackShiftingInfo> GetShiftToRop(uint64_t from_offset,
                                                     uint64_t byte_size,
                                                     bool include_extra_slot,
                                                     uint64_t min_rop_start = 0
                                                  );

    /**
     * @brief Internal helper function to find a sequence of stack shift gadgets using a breadth-first search.
     *
     * The search aims to find a path of stack shifts that results in a stack pointer
     * offset that meets either the minimum target offset or provides sufficient free space.
     *
     * @param from_offset The starting offset of the stack pointer.
     * @param min_to_offset An optional minimum desired offset for the stack pointer.
     * @param min_next_space An optional minimum required free space at the final stack pointer offset.
     * @return An optional StackShiftingInfo object. Contains a value if a sequence of shifts is found, otherwise `std::nullopt`.
     * @throws ExpKitError if both `min_to_offset` and `min_next_space` are not set.
     */
    std::optional<StackShiftingInfo> FindShiftsInternal(
        uint64_t from_offset, std::optional<uint64_t> min_to_offset,
        std::optional<uint64_t> min_next_space);

    /**
     * @brief Converts a chain of StackShiftPivot gadgets into a StackShiftingInfo structure.
     *
     * This function calculates the resulting offsets and populates the `StackShiftInfo`
     * vector based on the provided chain of gadgets and the starting offset.
     *
     * @param chain The vector of StackShiftPivot gadgets forming the chain.
     * @param from_offset The starting offset of the stack pointer before the shifts.
     * @return A StackShiftingInfo structure describing the sequence of shifts.
     */
    StackShiftingInfo GetShiftInfoFromChain(
        const std::vector<StackShiftPivot>& chain, uint64_t from_offset);

    /**
     * @brief Applies a sequence of stack shifts to the payload to reach at least a minimum target offset.
     *
     * @param kaslr_base The Kernel Address Space Layout Randomization base address.
     * @param from_offset The starting offset of the stack pointer.
     * @param min_to_offset The minimum desired offset for the stack pointer.
     * @return The final offset of the stack pointer after applying the shifts.
     * @throws ExpKitError if a suitable stack shift gadget sequence cannot be found.
     */
    uint64_t ApplyShift(uint64_t kaslr_base, uint64_t from_offset,
                        uint64_t min_to_offset);

    /**
     * @brief Attempts to find a stack pivot and a sequence of stack shifts
     * to pivot to a given Rop chain.
     *
     * @param rop The ROP chain to pivot to.
     * @return A RopPivotInfo structure containing information about the successful pivot and shifts.
     * @throws ExpKitError if a suitable pivot and shift sequence cannot be found.
     * @note This function iterates through found pivots and attempts to apply shifts until a working combination is found.
     */
    RopPivotInfo PivotToRop(const RopChain& rop);

    /**
     * @brief Finds a simple "pop rsp; ret" gadget that doesn't change the stack
     * before the RSP update and has its next RIP immediately after the gadget.
     *
     * @return An optional PopRspPivot. Contains a value if such a gadget is found, otherwise `std::nullopt`.
     */
    std::optional<PopRspPivot> GetPopRsp();

    /**
     * @brief Finds a simple "ret" gadget that shifts the stack by 8 bytes and jumps to the shifted location.
     *
     * @return A StackShiftPivot representing a simple "ret".
     */
    StackShiftPivot GetSingleRet();
};