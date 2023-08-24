exploit:
	gcc -o exploit exploit.c -lkeyutils -O0 -static -s

prerequisites:
	sudo apt-get install libkeyutils-dev
run:
	./exploit

clean:
	rm exploit
