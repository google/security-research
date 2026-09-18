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
#include <xdk/util/Register.h>

/**
 * @defgroup pivot_classes Pivot Classes
 * @brief Classes for stack pivoting and related techniques.
 */

/**
 * @ingroup pivot_classes
 * @brief Enum representing the type of indirect jump.
 */
enum class IndirectType { JMP, CALL };

/**
 * @ingroup pivot_classes
 * @brief Base struct for all pivot gadgets.
 */
struct Pivot {
    uint64_t address;
};

/**
 * @ingroup pivot_classes
 * @brief Represents the usage of a register and the offsets relative to it that are used.
 */
struct RegisterUsage {
    /** @brief The register being used. */
    Register reg;
    /** @brief A vector of offsets relative to the register that are used. */
    std::vector<int64_t> used_offsets;
};

/**
 * @ingroup pivot_classes
 * @brief Represents a stack shifting pivot gadget.
 */
struct StackShiftPivot: Pivot {
    /** @brief The offset from the new stack pointer where the next return address is expected. */
    uint64_t ret_offset;
    /** @brief The amount by which the stack pointer is shifted. */
    uint64_t shift_amount;

    /**
     * @brief Checks if the gadget jumps to the shifted stack location.
     * @return True if the gadget jumps to the shifted stack location, false otherwise.
     */
    bool JumpsToShift() const { return ret_offset == shift_amount - 8; }
};

/**
 * @ingroup pivot_classes
 * @brief Represents a one-gadget pivot.
 */
struct OneGadgetPivot: Pivot {
    /** @brief Information about the register used for the pivot. */
    RegisterUsage pivot_reg;
    /** @brief The offset from the pivot register's value to the next instruction pointer. */
    int64_t next_rip_offset;
};

/**
 * @ingroup pivot_classes
 * @brief Represents a push indirect pivot gadget.
 */
struct PushIndirectPivot: Pivot {
    /** @brief The type of indirect jump (JMP or CALL). */
    IndirectType indirect_type;
    /** @brief Information about the register being pushed onto the stack. */
    RegisterUsage push_reg;
    /** @brief Information about the register containing the indirect address. */
    RegisterUsage indirect_reg;
    /** @brief The offset from the indirect register's value to the next instruction pointer. */
    int64_t next_rip_offset;
};

/**
 * @ingroup pivot_classes
 * @brief Represents a pop RSP pivot gadget.
 */
struct PopRspPivot: Pivot {
    /** @brief The change in the stack pointer before the RSP register is popped. */
    uint64_t stack_change_before_rsp;
    /** @brief The offset from the new RSP value to the next instruction pointer. */
    int64_t next_rip_offset;
};

/**
 * @ingroup pivot_classes
 * @brief A collection of different types of pivot gadgets.
 */
struct Pivots {
    /** @brief A vector of one-gadget pivots. */
    std::vector<OneGadgetPivot> one_gadgets;
    /** @brief A vector of push indirect pivots. */
    std::vector<PushIndirectPivot> push_indirects;
    /** @brief A vector of pop RSP pivots. */
    std::vector<PopRspPivot> pop_rsps;
    /** @brief A vector of stack shifting pivots. */
    std::vector<StackShiftPivot> stack_shifts;
};