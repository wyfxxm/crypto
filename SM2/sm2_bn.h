#ifndef SM2_BN_H
#define SM2_BN_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SM2_BN_WORDS 8

typedef struct {
    uint32_t v[SM2_BN_WORDS];
} sm2_bn;

typedef struct {
    uint32_t v[SM2_BN_WORDS * 2];
} sm2_bn512;

void sm2_bn_zero(sm2_bn *r);
void sm2_bn_copy(sm2_bn *r, const sm2_bn *a);
int sm2_bn_is_zero(const sm2_bn *a);
int sm2_bn_cmp(const sm2_bn *a, const sm2_bn *b);
void sm2_bn_from_bytes(sm2_bn *r, const uint8_t in[32]);
void sm2_bn_to_bytes(const sm2_bn *a, uint8_t out[32]);

uint32_t sm2_bn_add(sm2_bn *r, const sm2_bn *a, const sm2_bn *b);
uint32_t sm2_bn_sub(sm2_bn *r, const sm2_bn *a, const sm2_bn *b);
void sm2_bn_add_mod(sm2_bn *r, const sm2_bn *a, const sm2_bn *b, const sm2_bn *mod);
void sm2_bn_sub_mod(sm2_bn *r, const sm2_bn *a, const sm2_bn *b, const sm2_bn *mod);

void sm2_bn_mul(sm2_bn512 *r, const sm2_bn *a, const sm2_bn *b);
void sm2_bn_mod(sm2_bn *r, const sm2_bn512 *a, const sm2_bn *mod);
void sm2_bn_mod_simple(sm2_bn *r, const sm2_bn *a, const sm2_bn *mod);
void sm2_bn_mod_mul(sm2_bn *r, const sm2_bn *a, const sm2_bn *b, const sm2_bn *mod);
void sm2_bn_mod_exp(sm2_bn *r, const sm2_bn *a, const sm2_bn *exp, const sm2_bn *mod);
void sm2_bn_mod_inv(sm2_bn *r, const sm2_bn *a, const sm2_bn *mod);

int sm2_bn_get_bit(const sm2_bn *a, int bit);
int sm2_bn_bit_length(const sm2_bn *a);
void sm2_bn_add_u32(sm2_bn *r, const sm2_bn *a, uint32_t v, const sm2_bn *mod);
void sm2_bn_sub_u32(sm2_bn *r, const sm2_bn *a, uint32_t v, const sm2_bn *mod);

#ifdef __cplusplus
}
#endif

#endif
