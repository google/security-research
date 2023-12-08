elf_targets=$(shell find . -name '*.elf.asm' -type f -printf "%f\n" | sed 's/\.asm//' | xargs)
bin_targets=$(shell find . -name '*.bin.asm' -type f -printf "%f\n" | sed 's/\.asm//' | xargs)
test_targets=$(shell find . -name '*.gdb' -type f -printf "%f\n" | sed 's/\.gdb/.gdb.out/' | xargs)

.PHONY: clean all test test_elf
all: $(elf_targets) $(bin_targets)

clean:
	rm -rf *.o *.elf *.bin

test: $(test_targets)

%.gdb.out: %
	gdb -n -batch-silent -x $^.gdb

%.bin.asm: third_party/*.asm
	touch $@

%.bin: %.bin.asm
	nasm -f bin $^ -o $@
	chmod +x $@

%.o: %.elf.asm
	nasm -g -F DWARF -f elf64 $^ -o $@

%.elf: %.o
	ld $^ -o $@
