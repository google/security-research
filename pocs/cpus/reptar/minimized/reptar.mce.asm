BITS 64

global _start

section .data
    data: times 128 db 0

;rax USED cpuid
;rbx USED cpuid
;rcx USED cpuid and rep movsb
;rdx USED cpuid
;rsi USED rep movsb
;rdi USED rep movsb
;rsp
;rbp
;r8 USED counter
;r9
;r10
;r11
;r12
;r13
;r14
;r15

section .text
    _start:
        push 0xDEADBEEF
        mov r8, 0
        .first_reptar:
        clflush [data]
        clflush [data+64]
        mov rsi, data
        mov rdi, data
        inc rcx
        ; first repmovsb nothing happens, the flushes below will happen
        rep
        db 0x44; rex.r
        movsb
        pause
        .second_reptar:
        clflush [data]
        clflush [data+64]
        dec rsi
        dec rdi
        inc rcx
        ; second repmovsb, the following 3 bytes are skipped when decoding
        rep
        db 0x44; rex.r
        movsb
        rep ; must be a prefix
        push rcx ; ignored
        push rcx ; ignored
        mov rax, data
        .many_reptars:
        %rep 0
            clflush [rax]
            clflush [rax+64]
            xor rax, rax
            dec rsi
            dec rdi
            inc rcx
            rep
            db 0x44; rex.r
            movsb
            pause
            mov rax, data
            xor rcx, rcx
        %endrep
        nop
        times 1024 int3
