BITS 64

global _start

%define SYS_sched_yield 0x18
%define SYS_write 0x01
%define SYS_exit 0x3c

section .data
    align 32
    secret:     times 4 dq 'SECRET'
    align 32
    regstate:   dq 0,0,0,0
    align 32
    space:      dd 1
section .text
_start:
    vmovdqu         ymm0, [rel secret]
    mov             rax, SYS_sched_yield
    syscall

    ; The value of ymm0 should now be zero.
    vpxor           ymm0, ymm0, ymm0

    ; Force a context switch.
    mov             rax, SYS_sched_yield
    syscall

    ; This sequence somehow "rolls" it back to the previous value?!?!
    ucomiss         xmm0, dword [rel space]
    mov             rax, SYS_sched_yield
    syscall

    ; We can dump it to stdout to verify.
    vmovdqu         [rel regstate], ymm0
    mov             rax, SYS_write
    mov             rdi, 1
    lea             rsi, [rel regstate]
    mov             rdx, 32
    syscall
    mov             rax, SYS_exit
    mov             rdi, 0
    syscall
    int3
