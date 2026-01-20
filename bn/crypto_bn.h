#ifndef CRYPTO_BN_H
#define CRYPTO_BN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef CRYPTO_BN_MAX_WORDS
#define CRYPTO_BN_MAX_WORDS 64
#endif

typedef struct {
    uint64_t v[CRYPTO_BN_MAX_WORDS];
    size_t words;
} crypto_bn;

void crypto_bn_zero(crypto_bn *r);
void crypto_bn_copy(crypto_bn *r, const crypto_bn *a);
int crypto_bn_is_zero(const crypto_bn *a);
int crypto_bn_cmp(const crypto_bn *a, const crypto_bn *b);

int crypto_bn_from_bytes(crypto_bn *r, const uint8_t *in, size_t len);
void crypto_bn_to_bytes(const crypto_bn *a, uint8_t *out, size_t len);

void crypto_bn_from_u64(crypto_bn *r, uint64_t value);
uint64_t crypto_bn_add(crypto_bn *r, const crypto_bn *a, const crypto_bn *b);
uint64_t crypto_bn_sub(crypto_bn *r, const crypto_bn *a, const crypto_bn *b);
int crypto_bn_mul(crypto_bn *r, const crypto_bn *a, const crypto_bn *b);

int crypto_bn_mod(crypto_bn *r, const crypto_bn *a, const crypto_bn *mod);
int crypto_bn_mod_mul(crypto_bn *r, const crypto_bn *a, const crypto_bn *b, const crypto_bn *mod);
int crypto_bn_mod_exp(crypto_bn *r, const crypto_bn *a, const crypto_bn *exp, const crypto_bn *mod);
int crypto_bn_mod_inv(crypto_bn *r, const crypto_bn *a, const crypto_bn *mod);

int crypto_bn_get_bit(const crypto_bn *a, size_t bit);
size_t crypto_bn_bit_length(const crypto_bn *a);

#ifdef __cplusplus
}
#endif

#endif
