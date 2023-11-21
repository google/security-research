all: reptar.loop reptar.loopless reptar.elf

reptar.elf: reptar.elf.asm
	nasm -f bin reptar.elf.asm -o reptar.elf
	chmod +x reptar.elf

%: %.o
	ld $^ -o $@

%.o: %.asm
	nasm -g -F DWARF -f elf64 $^ -o $@

clean:
	rm -rf *.o reptar.loop reptar.loopless reptar.elf
