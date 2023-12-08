BITS 64

%include "syscalls.asm"
%include "macros.asm"
%include "config.asm"

global icelake_repro
global icelake_buf

section .data
    align 4096
    dst: dq 0, 0
    src: dq 0, 0
section .text

    ; This should be aligned on a page boundary so that we can mprotect/madvise it.
    align 4096
icelake_repro:
        ; We ret on error, so save where we want to go.
        ; this is just because ret is a one-byte opcode.
        push    .finish
        xor     r8, r8                      ; iteration counter
        mov     rax, SYS32_sched_yield      ; this benchmarks better than syscall
        int     0x80
        xor     rcx, rcx
        align   32
        ; If you find an MCE difficult to repro, adjust this number for your SKU (try 0..8).
        times   2 nop
    .repeat:
        inc     r8                          ; keep track of executions
        inc     rcx                         ; movsb count
        lea     rdi, [rel dst]
        lea     rsi, [rel src]
        rep
        rex
        rex     r
        movsb
        rep     movsb
        jmp     short .repeat
     .after:
        lfence
        ; This should be unreachable
        times   128 ret
    .finish:
        mov     rax, r8
        ret
        hlt
