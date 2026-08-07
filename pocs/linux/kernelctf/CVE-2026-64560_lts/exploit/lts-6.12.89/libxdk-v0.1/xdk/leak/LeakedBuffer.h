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

class LeakedBuffer {
    Target& target_;
    std::vector<uint8_t> data_;

public:
    LeakedBuffer(Target& target, std::vector<uint8_t> data);

    uint64_t Read(uint64_t offset, size_t size);

    std::map<std::string, uint64_t> GetStruct(const std::string& struct_name, int64_t struct_offset = 0);
    uint64_t GetField(const std::string& struct_name, const std::string& field_name, int64_t struct_offset = 0);
};
