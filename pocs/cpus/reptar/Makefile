CFLAGS=-O0 -ggdb3 -march=icelake-server
LDFLAGS=-pthread -Wl,-z,noexecstack -static
NFLAGS=

.PHONY: clean

all: icebreak

%.o: %.asm
	nasm $(NFLAGS) -O0 -felf64 -o $@ $^

icebreak: main.o hammer.o threads.o util.o

clean:
	rm -f *.o core
	rm -f icebreak
