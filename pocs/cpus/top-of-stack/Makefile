.PHONY:all clean

CFLAGS += -g -O2 -finline-functions #-DIBPB

all: rsp

rsp: rsp.o
	gcc -static -o $@ $^

clean:
	rm -f *.o rsp
