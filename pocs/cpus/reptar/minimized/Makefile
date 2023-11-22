all: reptar.loop reptar.loopless reptar.vdsojmp.elf reptar.vdsopf.elf

%.elf: %.elf.asm
	nasm -f bin $^ -o $@
	chmod +x $@

%.out: %.o
	ld $^ -o $@

%.o: %.asm
	nasm -g -F DWARF -f elf64 $^ -o $@

clean:
	rm -rf *.o reptar.loop reptar.loopless reptar.vdsojmp.elf reptar.vdsopf.elf
