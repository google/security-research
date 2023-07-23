all:
	gcc -O0 -o victim victim.c 
	gcc -O0 -o attacker attacker.c -no-pie -masm=intel

clean:
	rm victim attacker