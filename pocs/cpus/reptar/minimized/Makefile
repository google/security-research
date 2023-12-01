elf_targets=$(shell find . -name '*.elf.asm' -type f -printf "%f\n" | sed 's/\.asm//' | xargs)
bin_targets=$(shell find . -name '*.bin.asm' -type f -printf "%f\n" | sed 's/\.asm//' | xargs)

all: $(elf_targets) $(bin_targets)
always-rebuild:

.PHONY: all clean always-rebuild

# always rebuild mce because it depends on env vars
reptar.mce.elf.asm: always-rebuild
	touch reptar.mce.elf.asm

%.bin.asm: third_party/*.asm
	touch $@

%.bin: %.bin.asm
	nasm -f bin $^ -o $@
	chmod +x $@

%.o: %.elf.asm
	nasm -g -F DWARF -f elf64 $^ -o $@

%.elf: %.o
	ld $^ -o $@

clean:
	rm -rf *.o *.elf *.bin
