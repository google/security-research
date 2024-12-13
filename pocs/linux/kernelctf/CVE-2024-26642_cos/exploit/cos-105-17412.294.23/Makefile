exploit:
	gcc -o exploit exploit.c -I/usr/include/libnl3 -lnl-nf-3 -lnl-route-3 -lnl-3 -static
prerequisites:
	sudo apt-get install libnl-nf-3-dev
run:
	./exploit

clean:
	rm exploit
