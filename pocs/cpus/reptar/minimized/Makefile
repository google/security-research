all: reptar.loop.out reptar.loopless.out reptar.mce.out reptar.align.out reptar.vdsojmp.elf reptar.vdsopf.elf

%.elf: %.elf.asm
	nasm -f bin $^ -o $@
	chmod +x $@

%.out: %.o
	ld $^ -o $@

%.o: %.asm
	nasm -g -F DWARF -f elf64 $^ -o $@

clean:
	rm -rf *.o *.out *.elf
