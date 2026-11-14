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

#include <sys/mman.h>
#include <cstring>
#include <xdk/payloads/RopChain.h>

/**
 * @defgroup rip_classes RIP Classes
 * @brief Classes related to Return-Oriented Programming (ROP) utilities.
 */

/**
 * @ingroup rip_classes
 * @class RopUtils
 * @brief Utility functions for ROP chain generation.
 */
class RopUtils {
public:
    /**
     * @brief Generates a ROP chain to return to user space after a kernel exploit.
     *
     * This function sets up a fake user stack and uses the KPTI trampoline to transition back to user space.
     * @param rop The RopChain object to add the return-to-user ROP action to.
     * @param after_lpe_func The address of the function to execute in user space after returning from the kernel.
     * @param stack_size The size of the fake user stack to allocate (default is 0x8000).
     * @param redzone_size The size of the redzone at the end of the fake user stack (default is 0x100).
     */
 static void Ret2Usr(RopChain& rop, void* after_lpe_func,
                     size_t stack_size = 0x8000, size_t redzone_size = 0x100);
};
