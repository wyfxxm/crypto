#include "sm4.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
    for (size_t i = 0; i < out_len; ++i) {
        unsigned int byte = 0;
        sscanf(hex + (i * 2), "%2x", &byte);
        out[i] = (uint8_t)byte;
    }
}

static void test_known_vector(void) {
    const char *key_hex = "0123456789abcdeffedcba9876543210";
    const char *pt_hex = "0123456789abcdeffedcba9876543210";
    const char *ct_hex = "681edf34d206965e86b3e94f536e4246";

    uint8_t key[16];
    uint8_t pt[16];
    uint8_t ct_expected[16];
    uint8_t ct[16];
    uint8_t decrypted[16];

    hex_to_bytes(key_hex, key, sizeof(key));
    hex_to_bytes(pt_hex, pt, sizeof(pt));
    hex_to_bytes(ct_hex, ct_expected, sizeof(ct_expected));

    sm4_key enc_key;
    sm4_set_encrypt_key(&enc_key, key);
    sm4_encrypt_block(&enc_key, pt, ct);
    assert(memcmp(ct, ct_expected, sizeof(ct)) == 0);

    sm4_key dec_key;
    sm4_set_decrypt_key(&dec_key, key);
    sm4_decrypt_block(&dec_key, ct, decrypted);
    assert(memcmp(decrypted, pt, sizeof(pt)) == 0);
}

int main(void) {
    test_known_vector();
    puts("SM4 tests passed.");
    return 0;
}
