#ifndef SM2_BN_H
#define SM2_BN_H

#include <stdint.h>
#include <stddef.h>

#include "crypto_bn.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SM2_BN_BYTES 32

typedef crypto_bn sm2_bn;
typedef crypto_bn sm2_bn512;

static inline void sm2_bn_zero(sm2_bn *r) {
    crypto_bn_zero(r);
}

static inline void sm2_bn_copy(sm2_bn *r, const sm2_bn *a) {
    crypto_bn_copy(r, a);
}

static inline int sm2_bn_is_zero(const sm2_bn *a) {
    return crypto_bn_is_zero(a);
}

static inline int sm2_bn_cmp(const sm2_bn *a, const sm2_bn *b) {
    return crypto_bn_cmp(a, b);
}

static inline void sm2_bn_from_bytes(sm2_bn *r, const uint8_t in[SM2_BN_BYTES]) {
    (void)crypto_bn_from_bytes(r, in, SM2_BN_BYTES);
}

static inline void sm2_bn_to_bytes(const sm2_bn *a, uint8_t out[SM2_BN_BYTES]) {
    crypto_bn_to_bytes(a, out, SM2_BN_BYTES);
}

static inline uint32_t sm2_bn_add(sm2_bn *r, const sm2_bn *a, const sm2_bn *b) {
    return (uint32_t)crypto_bn_add(r, a, b);
}

static inline uint32_t sm2_bn_sub(sm2_bn *r, const sm2_bn *a, const sm2_bn *b) {
    return (uint32_t)crypto_bn_sub(r, a, b);
}

static inline void sm2_bn_add_mod(sm2_bn *r, const sm2_bn *a, const sm2_bn *b, const sm2_bn *mod) {
    sm2_bn tmp;
    crypto_bn_add(&tmp, a, b);
    crypto_bn_mod(r, &tmp, mod);
}

static inline void sm2_bn_sub_mod(sm2_bn *r, const sm2_bn *a, const sm2_bn *b, const sm2_bn *mod) {
    sm2_bn tmp;
    if (crypto_bn_sub(&tmp, a, b)) {
        crypto_bn_add(&tmp, &tmp, mod);
    }
    crypto_bn_mod(r, &tmp, mod);
}

static inline void sm2_bn_mul(sm2_bn512 *r, const sm2_bn *a, const sm2_bn *b) {
    (void)crypto_bn_mul(r, a, b);
}

static inline void sm2_bn_mod(sm2_bn *r, const sm2_bn512 *a, const sm2_bn *mod) {
    (void)crypto_bn_mod(r, a, mod);
}

static inline void sm2_bn_mod_simple(sm2_bn *r, const sm2_bn *a, const sm2_bn *mod) {
    (void)crypto_bn_mod(r, a, mod);
}

static inline void sm2_bn_mod_mul(sm2_bn *r, const sm2_bn *a, const sm2_bn *b, const sm2_bn *mod) {
    (void)crypto_bn_mod_mul(r, a, b, mod);
}

static inline void sm2_bn_mod_exp(sm2_bn *r, const sm2_bn *a, const sm2_bn *exp, const sm2_bn *mod) {
    (void)crypto_bn_mod_exp(r, a, exp, mod);
}

static inline void sm2_bn_mod_inv(sm2_bn *r, const sm2_bn *a, const sm2_bn *mod) {
    (void)crypto_bn_mod_inv(r, a, mod);
}

static inline int sm2_bn_get_bit(const sm2_bn *a, int bit) {
    if (bit < 0) {
        return 0;
    }
    return crypto_bn_get_bit(a, (size_t)bit);
}

static inline int sm2_bn_bit_length(const sm2_bn *a) {
    return (int)crypto_bn_bit_length(a);
}

static inline void sm2_bn_add_u32(sm2_bn *r, const sm2_bn *a, uint32_t v, const sm2_bn *mod) {
    sm2_bn tmp;
    sm2_bn addend;
    crypto_bn_copy(&tmp, a);
    crypto_bn_from_u64(&addend, v);
    crypto_bn_add(&tmp, &tmp, &addend);
    crypto_bn_mod(r, &tmp, mod);
}

static inline void sm2_bn_sub_u32(sm2_bn *r, const sm2_bn *a, uint32_t v, const sm2_bn *mod) {
    sm2_bn tmp;
    sm2_bn subtrahend;
    crypto_bn_copy(&tmp, a);
    crypto_bn_from_u64(&subtrahend, v);
    if (crypto_bn_sub(&tmp, &tmp, &subtrahend)) {
        crypto_bn_add(&tmp, &tmp, mod);
    }
    crypto_bn_mod(r, &tmp, mod);
}

#ifdef __cplusplus
}
#endif

#endif
