.PHONY: all clean

all: leak_evict_x25519 leak_intermediate_x25519 leak_multiprocess x25519_victim

CFLAGS=-O3 -mrtm -static -masm=intel

boringssl/crypto/curve25519/fake_x25519.c: fake_x25519.c
	git clone https://boringssl.googlesource.com/boringssl || true
	cp fake_x25519.c boringssl/crypto/curve25519/fake_x25519.c

leak_intermediate_x25519: boringssl/crypto/curve25519/fake_x25519.c leak_intermediate_x25519.c
	cc $^  -o $@ $(CFLAGS) -Iboringssl/include

leak_multiprocess: boringssl/crypto/curve25519/fake_x25519.c leak_multiprocess.c
	cc $^  -o $@ $(CFLAGS) -Iboringssl/include

x25519_victim: boringssl/crypto/curve25519/curve25519.c x25519_victim.c
	cc $^  -o $@ $(CFLAGS) -Iboringssl/include -lssl -lcrypto

clean:
	- rm -rf leak_evict_x25519 leak_intermediate_x25519 leak_multiprocess x25519_victim boringssl
