#ifndef SM4_H
#define SM4_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t rk[32];
} sm4_key;

void sm4_set_encrypt_key(sm4_key *key, const uint8_t raw_key[16]);
void sm4_set_decrypt_key(sm4_key *key, const uint8_t raw_key[16]);

void sm4_encrypt_block(const sm4_key *key, const uint8_t in[16], uint8_t out[16]);
void sm4_decrypt_block(const sm4_key *key, const uint8_t in[16], uint8_t out[16]);

#ifdef __cplusplus
}
#endif

#endif
