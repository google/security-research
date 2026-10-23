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
#include <cstring>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>
#include "./include/xdk_device.h"
#include <xdk/util/Register.h>

#define DEVICE_PATH "/dev/xdk"

/**
 * @defgroup xdk_device_classes XDK Device Classes
 * @brief Classes for XDK device interaction.
 */

/**
 * @ingroup xdk_device_classes
 * @brief Enum representing the possible actions for RIP control.
 */
enum class RipAction { Jmp = 0x1, Call = 0x2, Ret = 0x3 };

/**
 * @ingroup xdk_device_classes
 * @brief Structure to hold information about a kernel function call log.
 */
struct CallLog {
    /** @brief The name of the function that was called. */
    std::string function_name;

    /** @brief A vector of arguments passed to the function. */
    std::vector<uint64_t> arguments;

    /** @brief The return value of the function. */
    uint64_t return_value;

    /** @brief The call stack at the time of the function call. */
    std::string call_stack;

    std::string GetSummary();
};

/**
 * @ingroup xdk_device_classes
 * @class XdkDevice
 * @brief Manages communication and data for the XDK device.
 */
class XdkDevice;

/**
 * @ingroup xdk_device_classes
 * @class Kprobe
 * @brief Class representing a Kprobe in the kernel.
 */
class Kprobe {
    kprobe_args args_;
    const size_t logs_size = 16 * 4096;
public:
    /**
     * @brief Constructor for the Kprobe class.
     * @param function_name The name of the function to probe.
     * @param arg_count The number of arguments to log (default is 0).
     * @param log_mode The logging mode (default is ENTRY_WITH_CALLSTACK | RETURN).
     * @param log_call_stack_filter An optional filter for the call stack (default is nullptr).
     */
    Kprobe(const char* function_name, uint8_t arg_count = 0,
           enum kprobe_log_mode log_mode = (kprobe_log_mode)(ENTRY_WITH_CALLSTACK | RETURN),
           const char* log_call_stack_filter = nullptr);

    /**
     * @brief Retrieves the call logs for this Kprobe.
     * @param clear_log Whether to clear the log after retrieving (default is
     * false).
     * @return A vector of CallLog structures.
     */
    std::vector<CallLog> GetCallLogs(bool clear_log = false);

    /**
     * @brief Prints the call logs for this Kprobe to the console.
     * @param clear_log Whether to clear the log after printing (default is false).
     */
    void PrintCallLog(bool clear_log = false);

    /**
     * @brief Destructor for the Kprobe class.
     */
    ~Kprobe();

    friend class XdkDevice;
};

/**
 * @ingroup xdk_device_classes
 * @class XdkDevice
 * @brief Class representing the interface to the xdk kernel module.
 */
class XdkDevice {
    /** @brief File descriptor for the xdk kernel module. */
    int fd_;

    /** @brief The default logging mode for Kprobes. */
    enum kprobe_log_mode default_log_mode_ = (kprobe_log_mode)(ENTRY_WITH_CALLSTACK | RETURN);

    /**
     * @brief A set of pointers to the Kprobe objects that have been successfully installed
     * in the kernel. This is used to keep track of probes that need to be removed
     * when the XdkDevice object is closed or destroyed.
     */
    std::set<Kprobe*> installed_probes_;

    /**
     * @brief Converts the provided RIP action and register map into a `rip_control_args` structure.
     * This structure is used to communicate with the kernel module for RIP control.
     * @param action The desired RIP action (Jump, Call, or Return).
     * @param regs A map of registers to set before performing the RIP action.
     * @return A `rip_control_args` structure populated with the provided action and registers.
     */
    rip_control_args ConvertRipArgs(
        RipAction action, const std::map<Register, uint64_t>& regs = {});

    /**
     * @brief Calls a raw ioctl command on the xdk device.
     * @param cmd The command to call.
     * @param arg The argument to the command.
     * @return The error code returned by the ioctl.
     * @throws ExpKitError if the ioctl returns an unknown error code.
     */
    xdk_error CallRaw(enum xdk_cmd cmd, void* arg) const;

public:
    /**
     * @brief Checks if the xdk device is available.
     * @return True if the device exists, false otherwise.
     */
    static bool IsAvailable();

    /**
     * @brief Constructor for the XdkDevice class.
     * @throws ExpKitError if the xdk device cannot be opened.
     */
    XdkDevice();

    /**
     * @brief Calls a xdk command and checks the error code.
     * @param cmd The command to call.
     * @param arg The argument to the command.
     * @param expected_error The expected error code if the command is not
     * successful.
     * @throws ExpKitError if the command was not successful and did not return
     * with expected_error.
     */
    xdk_error Call(enum xdk_cmd cmd, void* arg, xdk_error expected_error) const;

    /**
     * @brief Calls a xdk command expecting success.
     * @param cmd The command to call.
     * @param arg The argument to the command.
     * @throws ExpKitError if the command was not successful.
     */
    void Call(enum xdk_cmd cmd, void* arg) const;

    /**
     * @brief Allocates a buffer in kernel space.
     * @param size The size of the buffer to allocate.
     * @param gfp_account Whether to account for GFP_KERNEL allocations.
     * @return The kernel address of the allocated buffer.
     */
    uint64_t AllocBuffer(uint64_t size, bool gfp_account) const;

    /**
     * @brief Allocates a buffer in kernel space and copies data into it.
     * @param data The data to copy into the buffer.
     * @param gfp_account Whether to account for GFP_KERNEL allocations.
     * @return The kernel address of the allocated buffer.
     */
    uint64_t AllocBuffer(const std::vector<uint8_t>& data, bool gfp_account) const;

    /**
     * @brief Reads data from kernel space.
     * @param ptr The kernel address to read from.
     * @param size The number of bytes to read.
     */
    std::vector<uint8_t> Read(uint64_t ptr, uint64_t size) const;

    /**
     * @brief Writes data to kernel space.
     * @param ptr The kernel address to write to.
     * @param data The data to write.
     */
    void Write(uint64_t ptr, const std::vector<uint8_t>& data) const;

    /**
     * @brief Frees a kernel buffer.
     * @param ptr The kernel address of the buffer to free.
     */
    void Kfree(uint64_t ptr) const;

    /**
     * @brief Prints a message to the kernel log.
     * @param msg The message to print.
     */
    void Printk(const char* msg) const;

    /**
     * @brief Gets the KASLR base address.
     * @return The KASLR base address.
     */
    uint64_t KaslrLeak();

    /**
     * @brief Gets the address of the win target function.
     * @return The address of the win target function.
     * @details If the win target is called (e.g. via ROP chain), then it sets a
     * win flag in the kernel which can be checked with the CheckWin() function.
     */
    uint64_t WinTarget();

    /**
     * @brief Gets the address of a kernel symbol if it exists in kallsyms.
     * @param name The name of the symbol.
     * @return An optional containing the address of the symbol if found, otherwise
     * an empty optional.
     */
    std::optional<uint64_t> SymAddrOpt(const char* name);

    /**
     * @brief Gets the address of a kernel symbol if it exists in kallsyms.
     * @param name The name of the symbol.
     * @throws ExpKitError if the symbol was not found in kallsyms.
     * @return The address of the symbol.
     */
    uint64_t SymAddr(const char* name);

    /**
     * @brief Controls the RIP and other registers in the kernel.
     * @param args The arguments for controlling the RIP and registers.
     */
    void RipControl(const rip_control_args& args);

    /**
     * @brief Controls the RIP and other registers in the kernel.
     * @param action The action to perform (Jump, Call, or Return).
     * @param regs A map of registers to set and their values.
     */
    void RipControl(RipAction action,
                    const std::map<Register, uint64_t>& regs = {});

    /**
     * @brief Calls a kernel function at a specific address (with the "call" asm
     * call).
     * @param addr The address of the function to call.
     * @param regs A map of registers to set before the call.
     */
    void CallAddr(uint64_t addr, const std::map<Register, uint64_t>& regs = {});

    /**
     * @brief Jumps to a specific address in the kernel (with the "jmp" asm call).
     * @param addr The address to jump to.
     * @param regs A map of registers to set before the jump.
     */
    void JumpToAddr(uint64_t addr, const std::map<Register, uint64_t>& regs = {});

    /**
     * @brief Sets the RSP and performs a return ("mov rsp, <new_rsp>; ret").
     * @param new_rsp The new value for the RSP.
     * @param regs A map of registers to set before the return.
     */
    void SetRspAndRet(uint64_t new_rsp,
                     const std::map<Register, uint64_t>& regs = {});

    /**
     * @brief Gets the recovery address for RIP control.
     * @return The recovery address.
     */
    uint64_t GetRipControlRecoveryAddr();

    /**
     * @brief Installs a Kprobe in the kernel.
     * @param function_name The name of the function to probe.
     * @param arg_count The number of arguments to log (default is 0).
     * @param log_mode The logging mode (default is ENTRY_WITH_CALLSTACK | RETURN).
     * @param log_call_stack_filter An optional filter for the call stack (default
     * is nullptr which means no call stack filtering, all calls are recorded).
     * @return A pointer to the installed Kprobe object.
     */
    Kprobe* InstallKprobe(const char* function_name, uint8_t arg_count = 0,
                          enum kprobe_log_mode log_mode =
                              (kprobe_log_mode)(ENTRY_WITH_CALLSTACK | RETURN),
                          const char* log_call_stack_filter = nullptr);

    /**
     * @brief Removes an installed Kprobe.
     * @param probe A pointer to the Kprobe object to remove.
     */
    void RemoveKprobe(Kprobe* probe);

    /**
     * @brief Prints the call logs for all installed Kprobes.
     * @param clear_log Whether to clear the logs after printing (default is
     * false).
     */
    void PrintAllCallLog(bool clear_log = false);

    /**
     * @brief Checks if the win target has been called.
     */
    void CheckWin();

    /**
     * @brief Closes the connection to the xdk device and removes all installed
     * Kprobes.
     */
    void Close();

    ~XdkDevice();
};