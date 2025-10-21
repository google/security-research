CC = gcc
MUSL_CC = musl-gcc
CFLAGS =-fPIC -w
all: libx.c libx.h kaslr.c fuse.c
	$(CC) $(CFLAGS) -c kaslr.c -o kaslr.o
	$(CC) $(CFLAGS) -c net.c -o net.o
	$(CC) $(CFLAGS) -masm=intel -c ./libx.c -o ./libx.o
	$(CC) $(CFLAGS) -shared -o libx.so libx.o kaslr.o net.o 
	ar rcs libx.a libx.o kaslr.o net.o
musl: libx.c libx.h kaslr.c fuse.c
	$(MUSL_CC) $(CFLAGS) -c kaslr.c -o kaslr.o
	$(MUSL_CC) $(CFLAGS) -c net.c -o net.o
	$(MUSL_CC) $(CFLAGS) -masm=intel -c ./libx.c -o ./libx.o  -D_FILE_OFFSET_BITS=64
	$(MUSL_CC) $(CFLAGS) -shared -o libx.so libx.o kaslr.o net.o 
	ar rcs libx.a libx.o kaslr.o net.o
fuse: libx.c libx.h kaslr.c fuse.c
	$(CC) $(CFLAGS) -c kaslr.c -o kaslr.o -D_FILE_OFFSET_BITS=64
	$(CC) $(CFLAGS) -c -c fuse.c -o fuse.o -lpthread -lfuse -D_FILE_OFFSET_BITS=64
	$(CC) $(CFLAGS) -c net.c -o net.o -D_FILE_OFFSET_BITS=64
	$(CC) $(CFLAGS) -DCONFIG_FUSE -masm=intel -c ./libx.c -o ./libx.o  -D_FILE_OFFSET_BITS=64
	$(CC) $(CFLAGS) -shared -o libx.so libx.o kaslr.o net.o fuse.o
	ar rcs libx.a libx.o kaslr.o fuse.o net.o
test: main.c
	$(CC) $(CFLAGS) -masm=intel ./main.c -o ./main --static -L . -lx && ./main
clean:
	rm -rf ./libx.o ./libx.so ./libx.a ./net.o ./kaslr.o ./fuse.o
install: libx.so
	cp ./libx.so /lib/x86_64-linux-gnu/
	cp ./libx.a /lib/x86_64-linux-gnu/
	cp ./libx.h /usr/include/
install-musl: libx.so
	cp ./libx.so /lib/x86_64-linux-musl/
	cp ./libx.a /lib/x86_64-linux-musl/
	cp ./libx.h /usr/include/x86_64-linux-musl/
uninstall: 
	rm -rf /lib/x86_64-linux-gnu/libx.so
	rm -rf /lib/x86_64-linux-gnu/libx.a
	rm -rf /usr/include/libx.h
uninstall-musl: 
	rm -rf /lib/x86_64-linux-musl/libx.so
	rm -rf /lib/x86_64-linux-musl/libx.a 
	rm -rf /usr/include/x86_64-linux-musl/libx.h