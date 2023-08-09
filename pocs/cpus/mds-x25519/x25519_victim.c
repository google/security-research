#include <stdint.h>
#include <stdio.h>

int X25519(uint8_t out_shared_key[32],
           const uint8_t private_key[32],
           const uint8_t peer_public_value[32]);
void X25519_public_from_private(uint8_t out_public_value[32],
                                const uint8_t private_key[32]);

int main() {
  const uint8_t* priv = (const uint8_t*)"privtest12345678somemorebitsABCD";
  uint8_t clientpriv[32] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
                            17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
  uint8_t pub[32];
  X25519_public_from_private(pub, clientpriv);
  for (int i = 0; i < 32; i++) {
    printf("%02x ", pub[i]);
  }
  printf("\n");
  uint8_t out[32];
  while (1) {
    X25519(out, priv, pub);
  }
}
