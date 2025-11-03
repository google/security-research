CROSS ?=

all: anc eviction_anc

.PHONY: clean

anc: anc.c lib.c
	    $(CROSS)gcc -static -O0 -o $@ $^

eviction_anc: eviction_anc.c lib.c
	    $(CROSS)gcc -static -O0 -o $@ $^

clean:
	    -rm anc eviction_anc
