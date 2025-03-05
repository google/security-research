BITS 64

global check_opcode_results
global lastexec
global ymm_fill

section .data
    lastexec:   dq 0
    align 32
    ymm_fill:
        dq 0xAAAAAAAAAAAAAAAA
        dq 0xAAAAAAAAAAAAAAAA
        dq 0xAAAAAAAAAAAAAAAA
        dq 0xAAAAAAAAAAAAAAAA
    rdi_saved:  dq 0


%macro check 1+
    section .data
        ; could use %str() but that breaks older nasm
        %defstr instr %1
        %%name: db instr,0
    section .text
        lea rax, [rel %%name]
        mov [rel lastexec], rax
        xor rax, rax
        mov qword [rdi + 0x8 * 16], r15  ; RFLAGS
        ; Fill YMM registers with a known pattern
        vmovdqa ymm0, yword [rel ymm_fill]
        vmovdqa ymm1, yword [rel ymm_fill]
        vmovdqa ymm2, yword [rel ymm_fill]
        vmovdqa ymm3, yword [rel ymm_fill]
        vmovdqa ymm4, yword [rel ymm_fill]
        vmovdqa ymm5, yword [rel ymm_fill]
        vmovdqa ymm6, yword [rel ymm_fill]
        vmovdqa ymm7, yword [rel ymm_fill]
        vmovdqa ymm8, yword [rel ymm_fill]
        vmovdqa ymm9, yword [rel ymm_fill]
        vmovdqa ymm10, yword [rel ymm_fill]
        vmovdqa ymm11, yword [rel ymm_fill]
        vmovdqa ymm12, yword [rel ymm_fill]
        vmovdqa ymm13, yword [rel ymm_fill]
        vmovdqa ymm14, yword [rel ymm_fill]
        vmovdqa ymm15, yword [rel ymm_fill]
        xor rcx, rcx  ; zero RCX for test usage
        mov r13, 0x000000005555aaaa  ; known pattern used for ALU testing
        mov r14, 0x202  ; set required flags
        ;or r14, 1  ; set CF
        push r14
        popf
        pushf
        pop r14  ; move the real value back
        lfence
        sfence
        mfence
        %1
        lfence
        sfence
        mfence
        pushf
        pop r15  ; sacrifice r15 to hold a clean RFLAGS
        cmp ax, 0x1337
        je _exit
%endmacro

section .text

check_opcode_results:
    push    rbp
    mov     rbp, rsp
    ;       scratch space
    sub     rsp, 0x100
    mov     [rel rdi_saved], rdi  ; save off cpu state argument
    check adc ah,ah
    check adc al, 0x80
    check adc al,[rsp]
    check adc cl,ah
    check adc ecx, 0x41414141
    check adc ecx, byte -0x7f
    check adc ecx,ecx
    check adc ecx,[rsp]
    check adc edx,esi
    check adc r11b, 0x80
    check aesdeclast xmm1,oword [rsp]
    check aesdeclast xmm1,xmm1
    check aesdec xmm1,oword [rsp]
    check aesdec xmm1,xmm1
    check aesenclast xmm1,oword [rsp]
    check aesenclast xmm1,xmm1
    check aesenc xmm1,oword [rsp]
    check aesenc xmm1,xmm1
    check aesimc xmm1,oword [rsp]
    check aesimc xmm1,xmm1
    check aeskeygenassist xmm1,xmm1, byte 0x80
    check lock adc [rsp],ch
    check lock adc byte [rsp], 0x80
    check lock adc [rsp],edx
    check lock adc dword [rsp], byte -0x7f
    check lock adc dword [rsp], 0x41414141
    check adc [rsp],cl
    check adc byte [rsp], 0x80
    check adc [rsp],ecx
    check adc dword [rsp], byte -0x7f
    check adc dword [rsp], 0x41414141
    check adc eax, 0x41414141
    check add al, 0x80
    check add ch,dl
    check add ch,ah
    check add cl, 0x80
    check add ah,[rsp]
    check add eax,ecx
    check add edx,ecx
    check add ecx, byte -0x7f
    check add esi, 0x41414141
    check add edx,[rsp]
    check lock add [rsp],al
    check lock add byte [rsp], 0x80
    check lock add [rsp],edx
    check lock add dword [rsp], byte -0x7f
    check lock add dword [rsp], 0x41414141
    check add byte [rsp], 0x80
    check add [rsp],ecx
    check add dword [rsp], byte +0x01
    check add dword [rsp], 0x41414141
    check add eax, 0x41414141
    check addpd xmm5,[rsp]
    check addpd xmm7,xmm4
    check addps xmm7,oword [rsp]
    check addps xmm2,xmm1
    check addsd xmm2,[rsp]
    check addsd xmm4,xmm0
    check addss xmm5,dword [rsp]
    check addss xmm6,xmm6
    check addsubpd xmm5,oword [rsp]
    check addsubpd xmm8,xmm14
    check addsubps xmm5,oword [rsp]
    check addsubps xmm3,xmm5
    check and al, 0x80
    check and cl,cl
    check and ah,ch
    check and cl, 0x80
    check and ch,[rsp]
    check and edx,ecx
    check and r11d,eax
    check and ecx, byte +0x01
    check and ecx, 0x41414141
    check and ecx,[rsp]
    check lock and [rsp],cl
    check lock and byte [rsp], 0x80
    check lock and [rsp],ecx
    check lock and dword [rsp], byte +0x01
    check lock and dword [rsp], 0x41414141
    check and [rsp],dl
    check and byte [rsp], 0x80
    check and [rsp],eax
    check and dword [rsp], byte -0x7f
    check and dword [rsp], 0x41414141
    check andnpd xmm5,[rsp]
    check andnpd xmm7,xmm2
    check andnps xmm1,oword [rsp]
    check andnps xmm2,xmm0
    check and eax, 0x41414141
    check andpd xmm7,[rsp]
    check andpd xmm6,xmm4
    check andps xmm3,oword [rsp]
    check andps xmm3,xmm4
    check bsf ecx,edx
    check bsf ecx,[rsp]
    check bsr ecx,ecx
    check bsr ecx,[rsp]
    check bswap esi
    check btc ecx,edx
    check btc ecx, byte 0x80
    check bt esi,eax
    check bt rax, byte 0x80
    check bt dword [rsp], byte 0x80
    check btr ecx,esi
    check btr rax, byte 0x80
    check bts esi,ecx
    check bts rcx, byte 0x80
    check cbw
    check cdq
    check cdqe
    check clc
    check cld
    check clflush [rsp]
    check cmc
    check cmovna esi,edx
    check cmovna eax,[rsp]
    check cmovc ecx,ecx
    check cmovc ecx,[rsp]
    check cmovng eax,ecx
    check cmovng edx,[rsp]
    check cmovl edx,ecx
    check cmovl esi,[rsp]
    check cmova ecx,esi
    check cmova ecx,[rsp]
    check cmovnc edx,ecx
    check cmovnc esi,[rsp]
    check cmovg ecx,ecx
    check cmovg eax,[rsp]
    check cmovnl esi,eax
    check cmovnl ecx,[rsp]
    check cmovno ecx,esi
    check cmovno edx,[rsp]
    check cmovpo eax,ecx
    check cmovpo edx,[rsp]
    check cmovns ecx,ecx
    check cmovns ecx,[rsp]
    check cmovnz ecx,ecx
    check cmovnz edx,[rsp]
    check cmovo edx,ecx
    check cmovo ecx,[rsp]
    check cmovpe ecx,ecx
    check cmovpe ecx,[rsp]
    check cmovs ecx,ecx
    check cmovs eax,[rsp]
    check cmovz esi,edx
    check cmovz eax,[rsp]
    check cmp al, 0x80
    check cmp cl,dl
    check cmp ch,dl
    check cmp ah, 0x80
    check cmp ch,[rsp]
    check cmp ecx,ecx
    check cmp edx,eax
    check cmp ecx, byte -0x7f
    check cmp esi, 0x41414141
    check cmp eax,[rsp]
    check cmp [rsp],ah
    check cmp byte [rsp], 0x80
    check cmp [rsp],esi
    check cmp qword [rsp], byte -0x7f
    check cmp dword [rsp], 0x41414141
    check cmp eax, 0x41414141
    check lock cmpxchg16b oword [rsp]
    check cmpxchg16b oword [rsp]
    check lock cmpxchg8b qword [rsp]
    check cmpxchg8b qword [rsp]
    check cmpxchg al,dh
    check cmpxchg ecx,ecx
    check lock cmpxchg [rsp],cl
    check lock cmpxchg [rsp],edx
    check cmpxchg [rsp],ch
    check cmpxchg [rsp],edx
    check comisd xmm3,qword [rsp]
    check comisd xmm4,xmm3
    check comiss xmm3,dword [rsp]
    check comiss xmm6,xmm4
    check cpuid
    check cqo
    check crc32 ecx,ecx
    check crc32 ecx,cl
    check cvtdq2pd xmm1,[rsp]
    check cvtdq2pd xmm6,xmm2
    check cvtdq2ps xmm7,[rsp]
    check cvtdq2ps xmm7,xmm6
    check cvtpd2dq xmm7,[rsp]
    check cvtpd2dq xmm3,xmm7
    check cvtpd2pi mm5,[rsp]
    check cvtpd2pi mm0,xmm4
    check cvtpd2ps xmm2,[rsp]
    check cvtpd2ps xmm3,xmm3
    check cvtpi2pd xmm3,[rsp]
    check cvtpi2pd xmm2,mm1
    check cvtpi2ps xmm10,qword [rsp]
    check cvtpi2ps xmm2,mm7
    check cvtps2dq xmm2,[rsp]
    check cvtps2dq xmm0,xmm5
    check cvtps2pd xmm2,[rsp]
    check cvtps2pd xmm0,xmm6
    check cvtps2pi mm3,qword [rsp]
    check cvtps2pi mm4,xmm3
    check cvtsd2si ecx,[rsp]
    check cvtsd2si eax,xmm6
    check cvtsd2si r11,[rsp]
    check cvtsd2si r11,xmm14
    check cvtsd2ss xmm0,[rsp]
    check cvtsd2ss xmm3,xmm0
    check cvtsi2sd xmm7,ecx
    check cvtsi2sd xmm11,r11
    check cvtsi2sd xmm3,dword [rsp]
    check cvtsi2sd xmm10,qword [rsp]
    check cvtsi2ss xmm6,esi
    check cvtsi2ss xmm9,r11
    check cvtsi2ss xmm7,dword [rsp]
    check cvtsi2ss xmm9,qword [rsp]
    check cvtss2sd xmm2,[rsp]
    check cvtss2sd xmm1,xmm4
    check cvtss2si ecx,[rsp]
    check cvtss2si ecx,xmm6
    check cvtss2si r11,[rsp]
    check cvtss2si r11,xmm8
    check cvttpd2dq xmm7,[rsp]
    check cvttpd2dq xmm6,xmm7
    check cvttpd2pi mm5,[rsp]
    check cvttpd2pi mm6,xmm5
    check cvttps2dq xmm1,[rsp]
    check cvttps2dq xmm4,xmm4
    check cvttps2pi mm0,[rsp]
    check cvttps2pi mm3,xmm6
    check cvttsd2si ecx,[rsp]
    check cvttsd2si ecx,xmm7
    check cvttsd2si r11,[rsp]
    check cvttsd2si r11,xmm14
    check cvttss2si esi,[rsp]
    check cvttss2si ecx,xmm4
    check cvttss2si r11,[rsp]
    check cvttss2si r11,xmm14
    check cwd
    check cwde
    check dec cl
    check dec ecx
    check lock dec byte [rsp]
    check lock dec dword [rsp]
    check dec byte [rsp]
    check dec dword [rsp]
    check emms
    check extrq xmm3, 0x80, 0x80
    check extrq xmm2,xmm4
    check f2xm1
    check fabs
    check fadd qword [rsp]
    check fadd dword [rsp]
    check faddp st2
    check fadd st4
    check fadd to st4
    check fbld tword [rsp]
    check fbstp tword [rsp]
    check fchs
    check fcmovbe st4
    check fcmove st3
    check fcmovnbe st7
    check fcmovnb st0
    check fcmovne st2
    check fcmovnu st3
    check fcmovu st0
    check fcomip st5
    check fcomi st3
    check fcompp
    check fcomp qword [rsp]
    check fcomp dword [rsp]
    check fcomp st6
    check fcom qword [rsp]
    check fcom dword [rsp]
    check fcom st7
    check fcos
    check fdecstp
    check fndisi
    check fdivp st0
    check fdivrp st2
    check fdivr qword [rsp]
    check fdivr dword [rsp]
    check fdivr st4
    check fdivr to st3
    check fdiv qword [rsp]
    check fdiv dword [rsp]
    check fdiv st3
    check fdiv to st5
    check fneni
    check ffreep st1
    check ffree st1
    check fiadd word [rsp]
    check fiadd dword [rsp]
    check ficomp word [rsp]
    check ficomp dword [rsp]
    check ficom word [rsp]
    check ficom dword [rsp]
    check fidivr word [rsp]
    check fidivr dword [rsp]
    check fidiv word [rsp]
    check fidiv dword [rsp]
    check fild qword [rsp]
    check fild word [rsp]
    check fild dword [rsp]
    check fimul word [rsp]
    check fimul dword [rsp]
    check fincstp
    check fist word [rsp]
    check fist dword [rsp]
    check fistp qword [rsp]
    check fistp word [rsp]
    check fistp dword [rsp]
    check fisttp qword [rsp]
    check fisttp word [rsp]
    check fisttp dword [rsp]
    check fisubr word [rsp]
    check fisubr dword [rsp]
    check fisub word [rsp]
    check fisub dword [rsp]
    check fld1
    check fldl2t
    check fldl2e
    check fldpi
    check fldlg2
    check fldln2
    check fldz
    check fldcw [rsp]
    check fnclex
    check fninit
    check fnop
    check fnsave [rsp]
    check fnsave [rsp]
    check fnstcw [rsp]
    check fnstenv [rsp]
    check fnstenv [rsp]
    check fnstsw ax
    check fnstsw [rsp]
    check fpatan
    check fprem1
    check fprem
    check fptan
    check frndint
    check frstor [rsp]
    check frstor [rsp]
    check fsetpm
    check fscale
    ;check fsqrt
    ;check fsincos
    ;check fsin
    check imul cl
    check imul ecx
    check imul ecx,ecx
    check imul esi,ecx, byte +0x01
    check imul ecx,ecx,dword 0x8596df52
    check imul ecx,[rsp]
    check imul ecx,[rsp], byte -0x7f
    check imul edx,[rsp],dword 0xb850953c
    check imul byte [rsp]
    check imul dword [rsp]
    check inc r8b
    check inc ecx
    check lock inc byte [rsp]
    check lock inc dword [rsp]
    check inc byte [rsp]
    check inc dword [rsp]
    check insertq xmm7,xmm0
    check insertq xmm3,xmm0, 0x80, 0x80
    check lar ecx,di
    check lar esi,[rsp]
    check lddqu xmm4,oword [rsp]
    check lea edx,[rsp]
    ;check lfs eax,[rsp]
    ;check lgs ecx,[rsp]
    check lsl ecx,cx
    check lsl ecx,[rsp]
    check lzcnt ecx,ecx
    check lzcnt eax,dword [rsp]
    check maxpd xmm3,xmm3
    check maxsd xmm7,[rsp]
    check maxsd xmm2,xmm4
    check maxss xmm1,dword [rsp]
    check maxss xmm5,xmm5
    check minpd xmm4,xmm3
    check minps xmm6,xmm7
    check minsd xmm1,xmm7
    check minss xmm7,xmm1
    check mov al,[rsp]
    check movapd xmm1,xmm6
    check movapd xmm1,xmm2
    check movaps xmm6,xmm7
    check movaps xmm0,xmm7
    check movddup xmm2,qword [rsp]
    check movddup xmm2,xmm7
    check movd eax,xmm1
    check movdqa xmm3,xmm3
    check movdqu xmm0,xmm1
    check movdqu xmm6,xmm6
    check movd xmm4,ecx
    check mov ch,dh
    check mov ch, 0x80
    check mov ch, 0x80
    check mov cl,[rsp]
    check mov ecx,ecx
    check mov ecx,ecx
    check mov r8d, 0x41414141
    check mov edx, 0x41414141
    check mov eax,[rsp]
    check mov edx,ds
    check movhlps xmm6,xmm7
    check movhpd qword [rsp],xmm1
    check movhpd xmm7,qword [rsp]
    check movhps qword [rsp],xmm10
    check movhps xmm2,qword [rsp]
    check movlhps xmm7,xmm5
    check movlpd qword [rsp],xmm6
    check movlpd xmm4,qword [rsp]
    check movlps qword [rsp],xmm7
    check movlps xmm7,qword [rsp]
    check mov [rsp],al
    check mov [rsp],cl
    check mov byte [rsp], 0x80
    check mov [rsp],ecx
    check mov dword [rsp], 0x41414141
    check mov [rsp],eax
    check mov [rsp],gs
    check movmskpd ecx,xmm3
    check movmskps edx,xmm7
    check movnti [rsp],eax
    check movnti [rsp],rcx
    check movntsd qword [rsp],xmm5
    check movntss dword [rsp],xmm3
    check mov eax,[rsp]
    check movq r11,xmm3
    check movq xmm10,rcx
    check movq xmm0,xmm7
    check movq xmm5,xmm6
    check movsd qword [rsp],xmm3
    check movsd xmm7,qword [rsp]
    check movsd xmm4,xmm7
    check movsd xmm1,xmm7
    check movshdup xmm1,xmm5
    check movsldup xmm7,xmm2
    check movss xmm3,xmm1
    check movss xmm1,xmm6
    check movsx ecx,cl
    check movsx eax,cl
    check movsx ecx,byte [rsp]
    check movsx ecx,word [rsp]
    check movupd oword [rsp],xmm4
    check movupd xmm4,oword [rsp]
    check movupd xmm3,xmm2
    check movupd xmm3,xmm7
    check movups oword [rsp],xmm3
    check movups xmm4,oword [rsp]
    check movups oword [rsp], xmm4
    check movups xmm3,xmm7
    check movups xmm1,xmm6
    check movzx eax,dx
    check movzx ecx,cl
    check movzx eax,byte [rsp]
    check movzx ecx,word [rsp]
    check mul cl
    check mul rcx
    check mul byte [rsp]
    check mul dword [rsp]
    check mulpd xmm6,xmm1
    check mulps xmm5,xmm5
    check mulsd xmm7,xmm1
    check mulss xmm0,xmm7
    check neg cl
    check neg ecx
    check lock neg byte [rsp]
    check lock neg dword [rsp]
    check neg dword [rsp]
    check nop
    check hint_nop0 edx
    check hint_nop1 edx
    check hint_nop2 esi
    check hint_nop3 ecx
    check hint_nop4 ecx
    check hint_nop5 ecx
    check hint_nop6 ecx
    check hint_nop7 ecx
    check hint_nop57 esi
    check hint_nop9 ecx
    check hint_nop23 ecx
    check hint_nop25 esi
    check hint_nop36 ecx
    check hint_nop46 ecx
    check hint_nop50 ecx
    check bndstx [rsp],bnd3
    check bndldx bnd3,[rsp]
    check hint_nop4 dword [rsp]
    check hint_nop5 dword [rsp]
    check hint_nop62 dword [rsp]
    check hint_nop8 dword [rsp]
    check hint_nop38 dword [rsp]
    check hint_nop40 dword [rsp]
    check hint_nop55 dword [rsp]
    check not ah
    check not eax
    check lock not byte [rsp]
    check lock not dword [rsp]
    check not byte [rsp]
    check not dword [rsp]
    check or al, 0x80
    check or ch,ah
    check or ch,ah
    check or dl, 0x80
    check or ch,[rsp]
    check or ecx,esi
    check or ecx,ecx
    check or rcx, byte -0x7f
    check or ecx, 0x41414141
    check or ecx,[rsp]
    check lock or [rsp],al
    check xacquire lock or byte [rsp], 0x80
    check lock or [rsp],ecx
    check lock or dword [rsp], byte +0x01
    check lock or dword [rsp], 0x41414141
    check or [rsp],ah
    check o16 or byte [rsp], 0x80
    check or [rsp],ecx
    check or dword [rsp], byte -0x7f
    check or dword [rsp], 0x41414141
    check or eax, 0x41414141
    check orpd xmm0,xmm4
    check orps xmm1,xmm6
    check pause
    check popcnt edx,ecx
    check prefetch [rsp]
    check prefetchnta byte [rsp]
    check prefetcht0 byte [rsp]
    check prefetcht1 byte [rsp]
    check prefetcht2 byte [rsp]
    check prefetchw [rsp]
    check rcl ah,cl
    check rcl dh, byte 0x80
    check rcl ah,1
    check rcl esi,cl
    check rcl esi, byte 0x80
    check rcl ecx,1
    check rcl byte [rsp],cl
    check rcl byte [rsp], byte 0x80
    check rcl byte [rsp],1
    check rcl dword [rsp],cl
    check rcl dword [rsp], byte 0x80
    check rcl dword [rsp],1
    check rcr dl,cl
    check rcr dl, byte 0x80
    check rcr r11b,1
    check rcr ecx,cl
    check rcr esi, byte 0x80
    check rcr ecx,1
    check rcr byte [rsp],cl
    check rcr byte [rsp], byte 0x80
    check rcr byte [rsp],1
    check rcr dword [rsp],cl
    check rcr dword [rsp], byte 0x80
    check rcr dword [rsp],1
    check rdrand rax
    check rdseed rax
    check rdtsc
    check rdtscp
    check rol ah,cl
    check rol dl, byte 0x80
    check rol dh,1
    check rol edx,cl
    check rol eax, byte 0x80
    check rol ecx,1
    check rol byte [rsp],cl
    check rol byte [rsp], byte 0x80
    check rol byte [rsp],1
    check rol dword [rsp],cl
    check rol dword [rsp], byte 0x80
    check rol dword [rsp],1
    check ror r11b,cl
    check ror cl, byte 0x80
    check ror cl,1
    check ror edx,cl
    check ror ecx, byte 0x80
    check ror ecx,1
    check ror byte [rsp],cl
    check ror byte [rsp], byte 0x80
    check ror byte [rsp],1
    check ror dword [rsp],cl
    check ror dword [rsp], byte 0x80
    check ror qword [rsp],1
    check sahf
    check sar al,cl
    check sar cl, byte 0x80
    check sar ch,1
    check sar ecx,cl
    check sar edx, byte 0x80
    check sar cx,1
    check sar byte [rsp],cl
    check sar byte [rsp], byte 0x80
    check sar byte [rsp],1
    check sar dword [rsp],cl
    check sar dword [rsp], byte 0x80
    check sar dword [rsp],1
    check sbb al, 0x80
    check sbb ch,ch
    check sbb cl,cl
    check sbb cl, 0x80
    check sbb edx,ecx
    check sbb esi,ecx
    check sbb esi, byte -0x7f
    check sbb esi, 0x41414141
    check sbb ecx,[rsp]
    check lock sbb [rsp],ch
    check lock sbb byte [rsp], 0x80
    check lock sbb [rsp],eax
    check lock sbb dword [rsp], 0x41414141
    check sbb [rsp],dl
    check sbb byte [rsp], 0x80
    check sbb [rsp],ecx
    check sbb dword [rsp], byte +0x01
    check sbb dword [rsp], 0x41414141
    check sbb eax, 0x41414141
    check seto [rsp]
    check setz [rsp]
    check sgdt [rsp]
    check sha1msg1 xmm1,xmm1
    check sha1msg2 xmm1,xmm1
    check sha1nexte xmm1,xmm1
    check sha1rnds4 xmm1,xmm1,0
    check shld ecx,esi,cl
    check shld esi,ecx, 0x80
    check shld [rsp],eax,cl
    check shld [rsp],eax, 0x80
    check shl cl,cl
    check shl sil, byte 0x80
    check shl dh,1
    check shl ecx,cl
    check shl edx, byte 0x80
    check shl edx,1
    check shl byte [rsp],cl
    check shl byte [rsp], byte 0x80
    check shl byte [rsp],1
    check shl dword [rsp],cl
    check shl dword [rsp], byte 0x80
    check shl dword [rsp],1
    check shrd ecx,ecx,cl
    check shrd ecx,ecx, 0x80
    check shrd [rsp],edx,cl
    check shrd [rsp],ecx, 0x80
    check shr dl,cl
    check shr cl, byte 0x80
    check shr cl,1
    check shr ecx,cl
    check shr esi, byte 0x80
    check shr eax,1
    check shr byte [rsp],cl
    check shr byte [rsp], byte 0x80
    check shr byte [rsp],1
    check shr dword [rsp],cl
    check shr dword [rsp], byte 0x80
    check shr dword [rsp],1
    check sldt ecx
    check sldt [rsp]
    check smsw eax
    check smsw [rsp]
    check stc
    check std
    check stmxcsr dword [rsp]
    check str eax
    check str [rsp]
    check sub al, 0x80
    check sub cl,dh
    check sub cl,ch
    check sub cl, 0x80
    check sub cl,[rsp]
    check sub ecx,ecx
    check sub rcx,r11
    check sub ecx, byte +0x01
    check sub edx, 0x41414141
    check sub eax,[rsp]
    check lock sub [rsp],dh
    check xacquire lock sub byte [rsp], 0x80
    check lock sub [rsp],edx
    check xacquire lock sub dword [rsp], byte -0x7f
    check lock sub dword [rsp], 0x41414141
    check sub [rsp],ch
    check sub byte [rsp], 0x80
    check sub [rsp],rcx
    check sub dword [rsp], byte +0x01
    check sub dword [rsp], 0x41414141
    check sub eax, 0x41414141
    check test al, 0x80
    check test al,al
    check test dh, 0x80
    check test ecx,ecx
    check test ecx, 0x41414141
    check test [rsp],al
    check test byte [rsp], 0x80
    check test [rsp],esi
    check test qword [rsp],0xffffffffb5190aa6
    check test eax, 0x41414141
    check ucomisd xmm5,qword [rsp]
    check ucomisd xmm7,xmm5
    check ucomiss xmm5,dword [rsp]
    check ucomiss xmm5,xmm1
    check verr si
    check verr [rsp]
    check verw cx
    check verw [rsp]
    check vzeroupper
    check vzeroall
    check xadd ch,dl
    check xadd esi,ecx
    check lock xadd [rsp],dl
    check lock xadd [rsp],eax
    check xadd [rsp],cl
    check xadd [rsp],ecx
    check xchg al,ch
    check xchg esi,ecx
    check xchg eax,ecx
    check xchg ch,[rsp]
    check xchg ecx,[rsp]
    check xor al, 0x80
    check xor dh,cl
    check xor al, 0x80
    check xor ah,[rsp]
    check xor ecx,ecx
    check xor ecx,ecx
    check xor ecx, byte +0x01
    check xor ecx, 0x41414141
    check xor edx,[rsp]
    check lock xor [rsp],dl
    check lock xor byte [rsp], 0x80
    check lock xor [rsp],edx
    check xacquire lock xor dword [rsp], byte -0x7f
    check lock xor dword [rsp], 0x41414141
    check xor [rsp],cl
    check xor byte [rsp], 0x80
    check xor [rsp],eax
    check xor dword [rsp], byte -0x7f
    check xor dword [rsp], 0x41414141
    check xor eax, 0x41414141
    check xorpd xmm4,xmm7
    check xorps xmm7,xmm6
    ; Nothing discovered
    mov     rax, 0
_exit:
    mov     rdi, [rel rdi_saved]  ; restore RDI which points to saved state
    mov qword [rdi + 0x8 * 0], rax
    mov qword [rdi + 0x8 * 1], rcx
    mov qword [rdi + 0x8 * 2], rdx
    mov qword [rdi + 0x8 * 3], rbx
    mov qword [rdi + 0x8 * 4], rsp
    mov qword [rdi + 0x8 * 5], rbp
    mov qword [rdi + 0x8 * 6], rsi
    mov qword [rdi + 0x8 * 7], rdi
    mov qword [rdi + 0x8 * 8], r8
    mov qword [rdi + 0x8 * 9], r9
    mov qword [rdi + 0x8 * 10], r10
    mov qword [rdi + 0x8 * 11], r11
    mov qword [rdi + 0x8 * 12], r12
    mov qword [rdi + 0x8 * 13], r13
    mov qword [rdi + 0x8 * 14], r14
    mov qword [rdi + 0x8 * 15], r15
    vmovdqa [rdi + 0x8 * 20 + 0x20 * 0], ymm0
    vmovdqa [rdi + 0x8 * 20 + 0x20 * 1], ymm1
    vmovdqa [rdi + 0x8 * 20 + 0x20 * 2], ymm2
    vmovdqa [rdi + 0x8 * 20 + 0x20 * 3], ymm3
    vmovdqa [rdi + 0x8 * 20 + 0x20 * 4], ymm4
    vmovdqa [rdi + 0x8 * 20 + 0x20 * 5], ymm5
    vmovdqa [rdi + 0x8 * 20 + 0x20 * 6], ymm6
    vmovdqa [rdi + 0x8 * 20 + 0x20 * 7], ymm7
    vmovdqa [rdi + 0x8 * 20 + 0x20 * 8], ymm8
    vmovdqa [rdi + 0x8 * 20 + 0x20 * 9], ymm9
    vmovdqa [rdi + 0x8 * 20 + 0x20 * 10], ymm10
    vmovdqa [rdi + 0x8 * 20 + 0x20 * 11], ymm11
    vmovdqa [rdi + 0x8 * 20 + 0x20 * 12], ymm12
    vmovdqa [rdi + 0x8 * 20 + 0x20 * 13], ymm13
    vmovdqa [rdi + 0x8 * 20 + 0x20 * 14], ymm14
    vmovdqa [rdi + 0x8 * 20 + 0x20 * 15], ymm15
    mov     rsp, rbp
    pop     rbp
    ret
