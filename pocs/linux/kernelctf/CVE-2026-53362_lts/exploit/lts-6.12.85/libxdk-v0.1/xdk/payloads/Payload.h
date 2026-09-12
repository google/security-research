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
 * @file Payload.h
 * @brief Defines the Payload class for managing a contiguous block of memory.
 */
#pragma once

#include <cstdint>
#include <vector>
#include <optional>

/**
 * @defgroup payloads_classes Payloads Classes
 * @brief Classes for generating and managing payloads.
 */

/**
 * @ingroup payloads_classes
 * @class Payload
 * @brief Manages a dynamic, contiguous block of memory, tracking used sections.
 *
 * This class provides functionalities to allocate, reserve, release, and write
 * data to a buffer. It maintains a separate tracking mechanism to mark which
 * bytes in the buffer are considered "used" or "reserved". It also offers
 * methods to find empty contiguous blocks for new data.
 */
class Payload {
private:
    std::vector<uint8_t> data_;      ///< @brief The underlying data buffer.
    std::vector<bool> used_bytes_;   ///< @brief Tracks which bytes in `data_` are marked as used.
    uint64_t used_size_;             ///< @brief The highest offset that has been marked as used.

public:
    /**
     * @brief Constructs a new Payload object with a specified size.
     *
     * Initializes the internal data buffer and a corresponding `used_bytes`
     * tracking vector, marking all bytes as free initially.
     *
     * @param size The total size in bytes for the payload buffer.
     */
    Payload(int size);

    /**
     * @brief Copy constructor for the Payload class.
     *
     * Creates a new Payload object by deep-copying the data, used bytes map,
     * and used size from another Payload instance.
     *
     * @param other The Payload object to copy from.
     */
    Payload(const Payload& other);

    /**
     * @brief Returns the total size of the internal data buffer.
     * @return The total size of the buffer in bytes.
     */
    size_t Size();

    /**
     * @brief Gets a reference to the raw internal data vector.
     * @warning Modifying this vector directly can lead to inconsistencies with `used_bytes_`.
     * @return A reference to the underlying `std::vector<uint8_t>` data buffer.
     */
    std::vector<uint8_t>& GetData();

    /**
     * @brief Returns a copy of the data that is currently marked as "used".
     * @return A new `std::vector<uint8_t>` containing the data from the beginning
     * of the buffer up to `used_size_`.
     */
    std::vector<uint8_t> GetUsedData() const;

    /**
     * @brief Checks if a specified range of bytes is free (not marked as used).
     *
     * @param offset The starting offset in the buffer to check.
     * @param len The length of the contiguous block to check.
     * @param throws If true, an ExpKitError is thrown if the range is not free
     * or out of bounds. If false, it simply returns `false`.
     * @return `true` if the entire range is free and within bounds, `false` otherwise.
     * @throws ExpKitError if `throws` is `true` and the range is out of bounds or occupied.
     */
    bool CheckFree(uint64_t offset, uint64_t len, bool throws = false);

    /**
     * @brief Reserves a contiguous block of memory and marks it as used.
     *
     * This method checks if the specified range is free. If so, it marks the
     * bytes as used and returns a pointer to the beginning of the reserved block
     * within the internal data buffer. It updates `used_size_` if the new
     * reservation extends beyond the previously used area.
     *
     * @param offset The starting offset in the buffer to reserve.
     * @param len The length of the contiguous block to reserve.
     * @return A `uint8_t*` pointer to the reserved memory location within the buffer.
     * @throws ExpKitError if the range is not free or out of bounds.
     */
    uint8_t* Reserve(uint64_t offset, uint64_t len);

    /**
     * @brief Releases a previously reserved block of memory.
     *
     * Marks the specified range of bytes as free. If the released block was
     * at the end of the `used_size_` area, `used_size_` is adjusted downwards.
     *
     * @param offset The starting offset of the block to release.
     * @param len The length of the block to release.
     */
    void Release(uint64_t offset, uint64_t len);

    /**
     * @brief Reserves space for a `uint64_t` at a given offset.
     * @warning This function assumes the underlying buffer's memory address
     * will not change during its lifetime, which is generally true
     * for `std::vector` unless it's resized.
     * @param offset The starting offset for the `uint64_t`.
     * @return A `uint64_t*` pointer to the reserved memory location.
     * @throws ExpKitError if the space is not free or out of bounds.
     */
    uint64_t* ReserveU64(uint64_t offset);

    /**
     * @brief Reserves space for a `uint32_t` at a given offset.
     * @warning This function assumes the underlying buffer's memory address
     * will not change during its lifetime, which is generally true
     * for `std::vector` unless it's resized.
     * @param offset The starting offset for the `uint32_t`.
     * @return A `uint32_t*` pointer to the reserved memory location.
     * @throws ExpKitError if the space is not free or out of bounds.
     */
    uint32_t* ReserveU32(uint64_t offset);

    /**
     * @brief Sets a block of bytes in the payload.
     *
     * Reserves the specified range and then copies data from `src` into it.
     *
     * @param offset The starting offset in the payload.
     * @param src A pointer to the source data to copy.
     * @param len The number of bytes to copy.
     * @throws ExpKitError if the space is not free or out of bounds.
     */
    void Set(uint64_t offset, void* src, size_t len);

    /**
     * @brief Sets a block of bytes from a `std::vector` in the payload.
     *
     * Reserves the necessary space and then copies the bytes from the provided vector.
     *
     * @param offset The starting offset in the payload.
     * @param bytes The `std::vector` containing the data to copy.
     * @throws ExpKitError if the space is not free or out of bounds.
     */
    void Set(uint64_t offset, const std::vector<uint8_t>& bytes);

    /**
     * @brief Sets a 32-bit unsigned integer value at a specific offset.
     *
     * Reserves space for a `uint32_t` and writes the value.
     *
     * @param offset The starting offset in the payload.
     * @param value The `uint32_t` value to set.
     * @throws ExpKitError if the space is not free or out of bounds.
     */
    void SetU32(uint64_t offset, uint32_t value);

    /**
     * @brief Sets a 64-bit unsigned integer value at a specific offset.
     *
     * Reserves space for a `uint64_t` and writes the value.
     *
     * @param offset The starting offset in the payload.
     * @param value The `uint64_t` value to set.
     * @throws ExpKitError if the space is not free or out of bounds.
     */
    void SetU64(uint64_t offset, uint64_t value);

    /**
     * @brief Finds the first contiguous block of empty (unused) bytes of a given length.
     *
     * Searches for a free block starting from `min_offset`, respecting optional alignment.
     * The algorithm is O(n) where n is the size of the buffer.
     *
     * @param len The desired length of the empty block.
     * @param alignment The required alignment for the found offset (default is 1).
     * @param min_offset The minimum offset to start searching from (default is 0).
     * @return An `std::optional` containing the found offset if a suitable
     * block is found, or `std::nullopt` otherwise.
     */
    std::optional<uint64_t> FindEmpty(uint64_t len, uint64_t alignment = 1, uint64_t min_offset=0);

    /**
     * @brief Creates a snapshot of the current payload state.
     *
     * Returns a new Payload object that is a deep copy of the current instance's
     * data, used bytes, and used size. This can be used for rollback purposes.
     *
     * @return A new `Payload` object representing the current state.
     */
    Payload Snapshot();

    /**
     * @brief Restores the payload state from a given snapshot.
     *
     * Replaces the current instance's data, used bytes map, and used size with
     * those from the provided snapshot.
     *
     * @param snapshot The `Payload` object to restore from.
     */
    void Restore(const Payload& snapshot);
};