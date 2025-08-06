/* SPDX-License-Identifier: GPL-3.0-only */
#pragma once

#include <sys/mman.h>
#include <sys/syscall.h>

#include "defs.h"

/* Syscall wrappers. We want all of these to be inlined. */

static __always_inline u64 syscall6(u64 nr, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6)
{
    u64 ret;
    register u64 r10 asm("r10") = a4;
    register u64 r8 asm("r8") = a5;
    register u64 r9 asm("r9") = a6;

    /*
     * Syscall number in rax, arguments in rdi, rsi, rdx, r10, r8, r9
     * Clobbers rcx (return address) and r11 (flags).
     */
    asm volatile("syscall"
        : "=a"(ret)
        : "a"(nr),
          "D"(a1),
          "S"(a2),
          "d"(a3),
          "r"(r10),
          "r"(r8),
          "r"(r9)
        : "memory", "rcx", "r11"
    );

    return ret;
}

static __always_inline u64 syscall5(u64 nr, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5)
{
    u64 ret;
    register u64 r10 asm("r10") = a4;
    register u64 r8 asm("r8") = a5;

    asm volatile("syscall"
        : "=a"(ret)
        : "a"(nr),
          "D"(a1),
          "S"(a2),
          "d"(a3),
          "r"(r10),
          "r"(r8)
        : "memory", "rcx", "r11"
    );

    return ret;
}

static __always_inline u64 syscall4(u64 nr, u64 a1, u64 a2, u64 a3, u64 a4)
{
    u64 ret;
    register u64 r10 asm("r10") = a4;

    asm volatile("syscall"
        : "=a"(ret)
        : "a"(nr),
          "D"(a1),
          "S"(a2),
          "d"(a3),
          "r"(r10)
        : "memory", "rcx", "r11"
    );

    return ret;
}

static __always_inline u64 syscall3(u64 nr, u64 a1, u64 a2, u64 a3)
{
    u64 ret;

    asm volatile("syscall"
        : "=a"(ret)
        : "a"(nr),
          "D"(a1),
          "S"(a2),
          "d"(a3)
        : "memory", "rcx", "r11"
    );

    return ret;
}

static __always_inline u64 syscall2(u64 nr, u64 a1, u64 a2)
{
    u64 ret;

    asm volatile("syscall"
        : "=a"(ret)
        : "a"(nr),
          "D"(a1),
          "S"(a2)
        : "memory", "rcx", "r11"
    );

    return ret;
}

static __always_inline u64 syscall1(u64 nr, u64 a1)
{
    u64 ret;

    asm volatile("syscall"
        : "=a"(ret)
        : "a"(nr),
          "D"(a1)
        : "memory", "rcx", "r11"
    );

    return ret;
}

static __always_inline u64 syscall0(u64 nr)
{
    u64 ret;

    asm volatile("syscall"
        : "=a"(ret)
        : "a"(nr)
        : "memory", "rcx", "r11"
    );

    return ret;
}

static __always_inline int _sched_yield(void)
{
    return syscall0(SYS_sched_yield);
}

static void * _mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
    u64 ret = syscall6(SYS_mmap, (u64)addr, length, prot, flags, fd, offset);
    if ((i64)ret < 0) {
        return MAP_FAILED;
    }

    return (void *)ret;
}

static int _mprotect(void *addr, size_t len, int prot)
{
    return syscall3(SYS_mprotect, (u64)addr, len, prot);
}

static __always_inline int _munmap(void *addr, size_t len)
{
    return syscall2(SYS_munmap, (u64)addr, len);
}

static __always_inline noreturn void exit_group(int code)
{
    syscall1(SYS_exit_group, code);
    __builtin_unreachable();
}

static int arch_prctl(int code, u64 arg)
{
    return syscall2(SYS_arch_prctl, code, arg);
}

static int _prctl(int arg1, int arg2, int arg3, int arg4, int arg5)
{
    return syscall5(SYS_prctl, arg1, arg2, arg3, arg4, arg5);
}

static __always_inline int _madvise(void *addr, size_t length, int advice)
{
    return syscall3(SYS_madvise, (u64)addr, length, advice);
}
