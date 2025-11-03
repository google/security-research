CFLAGS=-std=gnu2x -Og -ggdb3 $(shell pkg-config --cflags $(PKGDEPS)) -mavx -march=znver2
CPPFLAGS=-Wall -W -D_GNU_SOURCE -DZENTOOL_VERSION=\"$(VERSION)\" -mavx -march=znver2
LDLIBS=$(shell pkg-config --libs $(PKGDEPS))
LDFLAGS=-Wl,-z,noexecstack
VERSION=0.01

# List of all required dependencies in pkg-config format.
PKGDEPS=openssl,gmp,json-c

.PHONY: clean distclean sync check template.bin

all: check zentool mcop mcas opcodes mtalk dumper

# build debug versions of all binaries
debug:	CFLAGS+=-fsanitize=address -O0
debug: clean all

# This is just to check all required packages are installed
.ONESHELL:
check:
	@pkg-config $(PKGDEPS) || {
		echo missing dependencies, try:
		echo     Debian: apt install pkg-config libssl-dev libgmp-dev libjson-c-dev nasm pahole
		echo     Fedora: dnf install pkg-config gmp-devel json-c-devel openssl-devel libasan nasm dwarves
		exit 1
	}
	@pahole --version > /dev/null || {
		echo missing dependency, try:
		echo    Debian: apt install pahole nasm
		echo    Fedora: dnf install dwarves nasm
		exit 1
	}
	@nasm --version > /dev/null || {
		echo missing dependency, try:
		echo    Debian: apt install nasm
		echo    Fedora: dnf install nasm
		exit 1
	}

sync: HOST=amdbench.cpu
sync:
	rsync --delete -azF . $(HOST):zentool/

%.o: %.asm
	nasm $(NFLAGS) -felf64 -o $@ $^

.ONESHELL:
%_fields.h: CLASS=$(patsubst %_fields.h,%,$@)
%_fields.h: structs.o ucode.h risc86.h
	pahole -C $(CLASS) $<  | awk 'BEGIN {
		print "/* This file was automatically generated */"
	}	/unsigned int/ && $$3 !~ /^_/ {
			printf("REGISTER_BITFIELD($(CLASS), %s);\n",gensub(/:.*/, "", 1, $$3))
		}' > $@

opcodes: CFLAGS=-fno-sanitize=address
opcodes: corechk.o

# This file is only used for generating bitfield headers.
structs.o: CFLAGS+=-O0

# This binary does some weird asm stuff for testing.
mtalk: LDFLAGS+=-O0

fields.o disas.o: RegOp_fields.h LdStOp_fields.h SpecOp_fields.h BrOp_fields.h SRegOp_fields.h

zentool: ucode.o risc86.o preimage.o fixup.o loader.o \
         dump.o options.o edit.o verify.o disas.o xxtea.o encrypt.o \
         util.o parse.o cpuid.o data.o symbols.o fields.o factor.o

mcas: disas.o options.o ucode.o parse.o ucode.o \
      risc86.o preimage.o options.o util.o cpuid.o factor.o dump.o data.o
mcop: ucode.o risc86.o disas.o util.o fields.o options.o \
      cpuid.o preimage.o factor.o dump.o data.o
mtalk: util.o options.o
dumper: dumper.o

# The automated tests use this file
template.bin: REVISION=$(shell printf "%08X" $$(grep -m1 -oP '^microcode\s+:\s+\K\S+' /proc/cpuinfo))
template.bin: zentool
	./zentool --output=$@ decrypt $(wildcard data/cpu????????_ver$(REVISION)_*.bin)
	./zentool edit --hdr-autorun false --nop all --match all=0 $@
	./zentool resign $@

clean:
	rm -f *.o zentool mcas mcop mtalk opcodes dumper template.bin
	rm -f zentool-$(VERSION).tar.gz

distclean: clean
	rm -f *_fields.h

dist: distclean
	@tmpfile=$$(mktemp)
	@tar	--directory=..                            \
		--exclude-vcs                                 \
		--exclude-vcs-ignores                         \
		--exclude-tag-all=.nobackup                   \
		--numeric-owner                               \
		--owner=:1000                                 \
		--group=:1000                                 \
		--gzip                                        \
		--create                                      \
		--transform="s#^zentool#zentool-$(VERSION)#"  \
		--file=$${tmpfile}                            \
		$(notdir $(abspath .))
	@mv $${tmpfile} zentool-$(VERSION).tar.gz
	@ls -l zentool-$(VERSION).tar.gz
