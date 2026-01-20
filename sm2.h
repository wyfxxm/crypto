#ifndef SM2_H
#define SM2_H

#include <stdint.h>
#include <stddef.h>
#include "sm2_bn.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    sm2_bn x;
    sm2_bn y;
    int infinity;
} sm2_point;

typedef struct {
    sm2_bn d;
    sm2_point public_key;
} sm2_key;

int sm2_generate_key(sm2_key *key);

int sm2_sign(const sm2_key *key, const uint8_t e[32], uint8_t r[32], uint8_t s[32]);
int sm2_verify(const sm2_point *pub, const uint8_t e[32], const uint8_t r[32], const uint8_t s[32]);

int sm2_encrypt(const sm2_point *pub, const uint8_t *msg, size_t msg_len, uint8_t **out, size_t *out_len);
int sm2_decrypt(const sm2_key *key, const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif
