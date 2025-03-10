BITS 64

; Can you make nasm macros for risc86?
; This is just an experiment...

%define rax reg2
%define rbx reg4

%define op_class(n)         (n << (4*8+27))

%define regop_type(n)       (n << (4*8+15))
%define regop_size(n)       (n << (4*8+10))
%define regop_sizemsb(n)    (n << (4*8+12))
%define regop_reg0(n)       (n << (0*8+21))
%define regop_reg1(n)       (n << (0*8+26))
%define regop_reg2(n)       (n << (0*8+31))
%define regop_rmod(n)       (n << (4*8+4))

%assign _quad 0

; .quad name sequence
%macro .quad 2
    %assign %1 _quad
    %assign _quad _quad + 1
    .quad %+ _quad:
    ; Sequence Word
    dd %2
%endmacro

%macro .uopcheck 0
    %if $ - .quad %+ %[_quad] >= 4+8*4
        %error A quad cannot contain more than four instructions
    %endif
%endmacro

%macro add 3
    .uopcheck
    ; how to check for immediates?
    %ifidn %3,reg4
        %error its reg4
    %endif
    %ifidn %2,reg2
        %error its reg2
    %endif
    dq op_class(7)          \
     | regop_type(0x5D)     \
     | regop_size(3)        \
     | regop_sizemsb(1)     \
     | regop_rmod(1)        \
     | regop_reg0(%3)       \
     | regop_reg1(%2)       \
     | regop_reg2(%1)
%endmacro

%define seq(n) (n)

.quad init, 7
    add rax, rax, rbx
    add rax, rax, rax
    add rax, rax, rax
    add rax, rax, rax
.quad hello, seq(init)
    add rax, rax, rbx
    add rax, rax, rbx
    add rax, rax, rbx
    add rax, rax, rbx
.quad seqname, seq(hello)
    add rax, rax, rbx
    add rax, rax, rbx
    add rax, rax, rbx
    add rax, rax, rbx
