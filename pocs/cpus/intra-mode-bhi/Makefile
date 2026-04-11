CFLAGS = -g -O3 -Wall -Wno-unused-function

all: main-for.o

TARGET = undef

main.o: src/main.c src/snippet.S
	nasm -f elf64 src/snippet.S -o snippet.o
	gcc -static -o $@ src/main.c snippet.o $(CFLAGS) -D$(TARGET)

main-for.o: src/main-for.c src/snippet-for.S
	nasm -f elf64 src/snippet-for.S -o snippet-for.o
	gcc -static -o $@ src/main-for.c snippet-for.o $(CFLAGS) -D$(TARGET)

clean:
	rm -f *.o
