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
#include <map>
#include <string>
#include <vector>
#include <xdk/pivot/Pivots.h>

/**
 * @defgroup target_classes Target Classes
 * @brief Classes for managing and representing targets.
 */

/**
 * @ingroup target_classes
 * @brief Enum for predefined ROP action IDs.
 */
enum struct RopActionId: uint32_t {
    MSLEEP = 0x01,
    COMMIT_INIT_TASK_CREDS = 0x02,
    SWITCH_TASK_NAMESPACES = 0x03,
    WRITE_WHAT_WHERE_64 = 0x04,
    FORK = 0x5,
    TELEFORK = 0x6,
    KPTI_TRAMPOLINE = 0x07,
};

/**
 * @ingroup target_classes
 * @brief Enum for the types of ROP items.
 */
enum struct RopItemType: uint8_t {
    CONSTANT_VALUE = 0,
    SYMBOL = 1,
    ARGUMENT = 2
};

/**
 * @ingroup target_classes
 * @brief Represents a single item in a ROP chain.
 */
struct RopItem {
    RopItemType type;
    uint64_t value;

    RopItem(RopItemType type, uint64_t value): type(type), value(value) { }
};

/**
 * @ingroup target_classes
 * @brief Metadata for a ROP action argument.
 */
struct RopActionArgMeta {
    std::string name;
    bool required;
    uint64_t default_value;

    RopActionArgMeta(std::string name, bool required, uint64_t default_value)
        : name(name), required(required), default_value(default_value) { }
};

/**
 * @ingroup target_classes
 * @brief Metadata for a ROP action.
 */
struct RopActionMeta {
    std::string desc;
    std::vector<RopActionArgMeta> args;

    RopActionMeta() {}
    RopActionMeta(std::string desc): desc(desc) { }
};

/**
 * @ingroup target_classes
 * @brief Represents a field within a struct.
 */
struct StructField {
    std::string name;
    uint64_t offset;
    uint64_t size;
};

/**
 * @ingroup target_classes
 * @brief Represents a kernel struct definition.
 */
struct Struct {
    std::string name;
    uint64_t size;
    std::map<std::string, StructField> fields;
};

/**
 * @ingroup target_classes
 * @class Target
 * @brief Represents a specific kernel target with its symbols, ROP gadgets, and other definitions.
 */
class Target {
protected:
    std::string distro;
    std::string release_name;
    std::string version;
    std::map<std::string, uint32_t> symbols;
    std::map<std::string, std::vector<RopItem>> rop_actions;
    std::map<std::string, Struct> structs;
    Pivots pivots;

public:
    /**
     * @brief Constructor for a Target.
     * @param distro The distribution name.
     * @param release_name The release name.
     * @param version The version string (optional).
     */
    Target(const std::string& distro, const std::string& release_name,
                 const std::string& version = "");

    const std::string& GetDistro() const;
    const std::string& GetReleaseName() const;
    const std::string& GetVersion() const;

    /**
     * @brief Get the offset of a symbol within the target.
     * @param symbol_name The name of the symbol.
     * @return The offset of the symbol.
     * @throws ExpKitError if the symbol is not found or has an offset of 0.
     */
    uint32_t GetSymbolOffset(std::string symbol_name);

    /**
     * @brief Get the ROP items for a specific ROP action ID.
     * @param id The ROP action ID.
     * @return A vector of ROP items for the specified action.
     * @throws ExpKitError if the ROP action ID is not found.
     */
    std::vector<RopItem> GetRopActionItems(RopActionId id);

    const Struct& GetStruct(const std::string& name);

    const Pivots& GetPivots();

    std::map<std::string, uint32_t> GetAllSymbols();

    /**
     * @brief Add a symbol to the target.
     * @param name The name of the symbol.
     * @param value The value (offset) of the symbol without the base address.
     */
    void AddSymbol(const std::string& name, uint64_t value);

    /**
     * @brief Add a ROP Action to the target.
     * @param name The name of the ROP Action.
     * @param value The ROP Action items (array of RopItem).
     */
    void AddRopAction(const std::string& name, std::vector<RopItem> value);

    /**
     * @brief Add a struct definition to the target.
     * @param value The struct structure
     */
    void AddStruct(const Struct& value);

    /**
     * @brief Add a struct definition to the target.
     * @param name The name of the struct.
     * @param size The size of the struct.
     * @param fields A vector of StructField objects representing the fields of the struct.
     */
    void AddStruct(const std::string& name, uint64_t size,
                    const std::vector<StructField>& fields);

    /**
     * @brief Sets the Pivots struct for the target.
     * @param pivots The pivots struct
     */
    void SetPivots(const Pivots& pivots);

    void Merge(const Target& src);

    uint64_t GetStructSize(const std::string& struct_name);
    uint64_t GetFieldOffset(const std::string& struct_name, const std::string& field_name);
    uint64_t GetFieldSize(const std::string& struct_name, const std::string& field_name);
};
