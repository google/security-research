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

#include <map>
#include <memory>
#include <optional>
#include <vector>
#include <xdk/target/Target.h>

class KxdbParser;
/**
 * @defgroup target_classes Target Classes
 * @brief Classes for managing and representing targets.
 */

/**
 * @ingroup target_classes
 * @class TargetDb
 * @brief Manages a database of kernel targets, including both static and dynamically parsed ones.
 */
class TargetDb {
    std::unique_ptr<KxdbParser> parser_;

    std::vector<Target> static_targets_;
    std::map<std::string, size_t> by_version_;
    std::map<std::string, size_t> by_distro_release_;

    /**
     * @brief Merges data from a source Target object into a destination Target object.
     * @param dst The destination Target object to merge into.
     * @param src The source Target object to merge from.
     */
    void MergeTargets(Target& dst, const Target& src);

    /**
     * @brief Retrieves a Target object, merging data from a KxdbParser target and a target if available.
     * @param target_opt An optional Target object parsed from a KXDB file.
     * @param static_idx An optional index of a target to merge.
     * @return The merged Target object.
     * @throws ExpKitError if both target_opt and static_idx are not provided.
     */
    Target GetTarget(std::optional<Target> target_opt,
                     std::optional<size_t> static_idx);

public:
    // declare destructor
    ~TargetDb();
    TargetDb() = default;

    /**
     * @brief Constructs a TargetDb object.
     * @param filename A database file to read from.
     */
    TargetDb(const std::string &filename);

    /**
     * @brief Constructs a TargetDb object from a byte buffer.
     * @param data The buffer containing the KXDB file data.
     */
    TargetDb(const std::vector<uint8_t>& data);

    /**
     * @brief Constructs a TargetDb object.
     * @param filename A database file to read from if exists.
     * @param fallback_kxdb The buffer containing the fallback / built-in KXDB file data if the file does not exists.
     */
    TargetDb(const std::string& filename, const std::vector<uint8_t>& fallback_kxdb);

    /**
     * @brief Adds a target to the database.
     * @param target The target to add.
     */
    void AddTarget(const Target& target);

    /**
     * @brief Retrieves a Target object by distro and release name.
     * @param distro The distribution name.
     * @param release_name The release name.
     * @return The Target object.
     */
    Target GetTarget(const std::string& distro,
                     const std::string& release_name);

    /**
     * @brief Retrieves a Target object by version.
     * @param version The version string.
     * @return The Target object.
     */
    Target GetTarget(const std::string& version);

    /**
     * @brief Automatically detects the target based on the system's kernel version.
     * @return The detected Target object.
     * @throws ExpKitError if the target cannot be detected.
     */
    Target AutoDetectTarget();
};