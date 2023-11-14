BITS 64

%include "syscalls.asm"
%include "macros.asm"
%include "config.asm"

section .text

global sibling_trigger
global sibling_fault

sibling_trigger:
        mfence
        mov     rax, SYS_sched_yield
        syscall
        jmp     sibling_trigger
        hlt

sibling_fault:
    .repeat:
        ud2
        jmp     .repeat
