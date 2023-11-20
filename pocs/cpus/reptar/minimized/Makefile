all: rexit

%: %.o
	ld $^ -o $@

%.o: %.asm
	nasm -g -F DWARF -f elf64 $^ -o $@

clean:
	rm -rf *.o rexit
