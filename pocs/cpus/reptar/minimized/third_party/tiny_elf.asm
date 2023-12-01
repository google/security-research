bits 64
; stolen from https://stackoverflow.com/questions/53382589/smallest-executable-program-x86-64
            org 0x7ffff7ff8000

%ifnmacro TINY_ELF_PAYLOAD
    %macro TINY_ELF_PAYLOAD 0
        _start:
    %endmacro
%endif

ehdr:                                           ; Elf64_Ehdr
            db  0x7F, "ELF", 2, 1, 1, 0         ;   e_ident
    times 8 db  0
            dw  2                               ;   e_type
            dw  62                              ;   e_machine
            dd  1                               ;   e_version
            dq  _start                          ;   e_entry
            dq  text_phdr - $$                  ;   e_phoff
            dq  0                               ;   e_shoff
            dd  0                               ;   e_flags
            dw  ehdrsize                        ;   e_ehsize
            dw  phdrsize                        ;   e_phentsize
            dw  1                               ;   e_phnum
            dw  0                               ;   e_shentsize
            dw  0                               ;   e_shnum
            dw  0                               ;   e_shstrndx

ehdrsize    equ $ - ehdr

text_phdr:                                      ; Elf64_Phdr
            dd  1                               ;   p_type
            dd  5                               ;   p_flags
            dq  0                               ;   p_offset
            dq  $$                              ;   p_vaddr
            dq  $$                              ;   p_paddr
            dq  textsize                        ;   p_filesz
            dq  textsize                        ;   p_memsz
            dq  0x1000                          ;   p_align

phdrsize    equ     $ - text_phdr

TINY_ELF_PAYLOAD

textsize      equ     $ - $$