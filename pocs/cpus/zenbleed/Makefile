VERSION=5
CFLAGS=-O0 -ggdb3 -march=znver2
LDFLAGS=-pthread -Wl,-z,noexecstack
NFLAGS=

.PHONY: clean dist

all: zenbleed

%.o: %.asm
	nasm $(NFLAGS) -O0 -felf64 -o $@ $^

zenbleed: zenleak.o pattern.o workqueue.o util.o

clean:
	rm -f *.o core
	rm -f zenbleed
	rm -f zenbleed-v*.tar.gz

dist: clean
	tar --exclude=".*" -C .. -zcvf ../zenbleed-v$(VERSION).tar.gz $(notdir $(CURDIR))
	mv ../zenbleed-v$(VERSION).tar.gz .
