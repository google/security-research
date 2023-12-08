%macro LONG_MODE_BOOT_PAYLOAD 0
    xor rbx, rbx
    xor ecx, ecx
    lea rsi, [rsp+1]
    mov rdi, rsi
    times 8*64*64/4 pause
    %rep 32*8 ; icache has 8 ways 64 sets
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
        pause
        align 64 ; icache line size
    %endrep
    jmp $
%endmacro

%include "third_party/long_mode_boot.asm"
