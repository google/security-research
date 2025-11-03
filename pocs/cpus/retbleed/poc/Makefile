# SPDX-License-Identifier: GPL-3.0-only
CFLAGS = -Os -g -Wall -Wextra -static -fno-asynchronous-unwind-tables -mno-red-zone -Wno-unused-function

all: leak_process_tree

# Shellcode
retbleed_shellcode: retbleed.c linker.ld syscalls.h defs.h retbleed.h offsets.h
	gcc $(CFLAGS) -DRETBLEED_STANDALONE -T linker.ld -nostdlib -mgeneral-regs-only -msse2 -o $@ $<

# Standalone ELF file, for testing
leak_process_tree: main.c syscalls.h defs.h retbleed.h offsets.h retbleed.c proclist.h proclist.c
	gcc $(CFLAGS) -o $@ retbleed.c main.c proclist.c

clean:
	-rm retbleed_shellcode leak_process_tree

.PHONY: clean
