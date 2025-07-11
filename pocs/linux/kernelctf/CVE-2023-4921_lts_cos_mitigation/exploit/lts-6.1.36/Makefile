INCLUDES = -I/usr/include/libnl3
LIBS = -L. -pthread -lnl-cli-3 -lnl-route-3 -lnl-3 -ldl -lkeyutils
CFLAGS = -fomit-frame-pointer -static

exploit: exploit.c
	gcc -o $@ exploit.c $(INCLUDES) $(CFLAGS) $(LIBS)

prerequisites:
	sudo apt-get install libnl-cli-3-dev libnl-route-3-dev libkeyutils-dev
