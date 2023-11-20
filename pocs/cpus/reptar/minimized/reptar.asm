BITS 64

global _start

section .data
    data: times 128 db 0

section .text
    _start:
        mov cl, 7
        mov eax, data
        .loop_for_every_iteration:
            mov rbx, cs
            push rbx
            push .loop_only_on_bug
            call far [rsp]
            .return_from_far_call:
            align 64
            .loop_only_on_bug:
                push rcx
                clflush [rax]
                clflush [rax+64]
                mov rsi, 0
                cmp cl, 7
                cmove rsi, rax ; only make a valid move if rcx is 7
                mov rdi, data
                mov cl, 1

                align 64
                .reptar:
                    rep
                    db 0x44; rex.r
                    movsb
                ; WHEN THE BUG TRIGGERS NOTHING BELOW HERE EXECUTES
                ; the instructions at loop_only_on_bug execute instead
                ; and the instruction pointer as seen by interrupts is
                ; the one as if the execution continued below
                .after_reptar:
                    rep
                    times 4 nop
                    jmp .skip_reptar_alias

                align 64
                ; this is aligned to match the rep rex.r movsb instruction
                .reptar_alias:
                    nop;rep
                    nop;rex.r
                    nop;movsb
                ; we cause a segfault on movsb above (by cmov rsi) but RIP will
                ; point here instead on the segfault.
                .after_reptar_alias:
                    times 100 int3

                .skip_reptar_alias:
                    mov cl, 7
                    align 32
                    call .loop_for_every_iteration
                .end_of_program:
                    nop
