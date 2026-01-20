#include "sm2.h"
#include "sm3.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void test_sign_verify(void) {
    sm2_key key;
    uint8_t digest[32];
    uint8_t r[32];
    uint8_t s[32];
    const char *message = "message digest";

    assert(sm2_generate_key(&key));
    sm3_hash((const uint8_t *)message, strlen(message), digest);

    assert(sm2_sign(&key, digest, r, s));
    assert(sm2_verify(&key.public_key, digest, r, s));
}

static void test_encrypt_decrypt(void) {
    sm2_key key;
    const uint8_t message[] = {
        0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x20,
        0x73, 0x74, 0x61, 0x6e, 0x64, 0x61, 0x72, 0x64
    };
    uint8_t *ciphertext = NULL;
    size_t ciphertext_len = 0;
    uint8_t *plaintext = NULL;
    size_t plaintext_len = 0;

    assert(sm2_generate_key(&key));

    assert(sm2_encrypt(&key.public_key, message, sizeof(message), &ciphertext, &ciphertext_len));
    assert(ciphertext != NULL);
    assert(ciphertext_len > 0);

    assert(sm2_decrypt(&key, ciphertext, ciphertext_len, &plaintext, &plaintext_len));
    assert(plaintext_len == sizeof(message));
    assert(memcmp(plaintext, message, sizeof(message)) == 0);

    free(ciphertext);
    free(plaintext);
}

int main(void) {
    test_sign_verify();
    test_encrypt_decrypt();
    puts("SM2 tests passed.");
    return 0;
}
