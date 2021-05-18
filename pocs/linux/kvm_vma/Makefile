all: poc

kernel_code: kernel_code.asm
	nasm $^ -o $@

guest_code: guest_code.asm
	nasm $^ -o $@

%.h: %
	xxd -i $^ | sed 's/unsigned/constexpr unsigned/' > $@

poc: poc.cc guest_code.h kernel_code.h
	g++ $^ -o $@ -std=c++17 -fno-pie -static

clean:
	rm -f poc guest_code.h kernel_code.h kernel_code guest_code

.PHONY: clean
