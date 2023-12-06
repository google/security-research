%define TINY_ELF_BASE_ADDRESS 0x7fffffffe000
%macro TINY_ELF_PAYLOAD 0
_start:
    lea rax, [rsp - 0x1000]
    mov r15, .skip_reptar_alias
    jmp r15
    align 16
    .loop_for_every_iteration:
    .loop_only_on_bug:
        clflush [rax]
        clflush [rax+64]
        mov rsi, rax
        mov rdi, rax
        mov cl, 1
        align 16
        inc rbp
        clflush [rax]
        clflush [rax+1]
        .reptar:
            rep
            db 0x44; rex.r
            movsb
        .after_reptar:
            pause
            times 64 nop
            jmp r15
        .skip_reptar_alias:
            inc rdx
            jmp .loop_for_every_iteration
        .end_of_program:
            int3
            int3
%endmacro

%include "third_party/tiny_elf.asm"
