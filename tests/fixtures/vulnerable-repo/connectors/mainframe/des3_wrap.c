#include <openssl/des.h>

/* Wraps PIN blocks for the legacy mainframe settlement connector — 3DES. */
void wrap_pin(const unsigned char *in, unsigned char *out, long len,
              DES_key_schedule *k1, DES_key_schedule *k2, DES_key_schedule *k3,
              DES_cblock *iv) {
    DES_ede3_cbc_encrypt(in, out, len, k1, k2, k3, iv, DES_ENCRYPT);
}
