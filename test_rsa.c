#include "rsa.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_rsa_size(size_t bits) {
    rsa_keypair keypair;
    rsa_public_key_bytes pub_bytes;
    rsa_private_key_bytes priv_bytes;

    assert(rsa_generate_key(&keypair, bits));
    assert(rsa_public_key_to_bytes(&keypair.pub, &pub_bytes));
    assert(rsa_private_key_to_bytes(&keypair.priv, &priv_bytes));

    uint8_t message[] = {0x12, 0x34, 0x56, 0x78, 0x9a};
    size_t n_len = pub_bytes.n_len;
    uint8_t padded_in[CRYPTO_BN_MAX_WORDS * 8];
    uint8_t ciphertext[CRYPTO_BN_MAX_WORDS * 8];
    uint8_t decrypted[CRYPTO_BN_MAX_WORDS * 8];

    memset(padded_in, 0, sizeof(padded_in));
    memcpy(padded_in + (n_len - sizeof(message)), message, sizeof(message));

    assert(rsa_public_bytes(&pub_bytes, ciphertext, n_len, padded_in, n_len));
    assert(rsa_private_bytes(&priv_bytes, decrypted, n_len, ciphertext, n_len));

    assert(memcmp(decrypted, padded_in, n_len) == 0);
}

int main(void) {
    test_rsa_size(1024);
    test_rsa_size(2048);
    test_rsa_size(4096);
    puts("RSA tests passed.");
    return 0;
}
