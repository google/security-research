nasm_targets=$(shell find . -name '*.asm' -type f ! -name '*.elf.asm' -printf "%f\n" | sed 's/\.asm/\.out/' | xargs)
elf_targets=$(shell find . -name '*.elf.asm' -type f -printf "%f\n" | sed 's/\.asm//' | xargs)

all: $(nasm_targets) $(elf_targets)

%.elf: %.elf.asm
	nasm -f bin $^ -o $@
	chmod +x $@

%.out: %.o
	ld $^ -o $@

%.o: %.asm
	nasm -g -F DWARF -f elf64 $^ -o $@

clean:
	rm -rf *.o *.out *.elf
