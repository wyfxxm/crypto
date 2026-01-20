#ifndef CRYPTO_RSA_H
#define CRYPTO_RSA_H

#include <stddef.h>
#include <stdint.h>

#include "crypto_bn.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    crypto_bn n;
    crypto_bn e;
} rsa_public_key;

typedef struct {
    crypto_bn n;
    crypto_bn d;
    crypto_bn p;
    crypto_bn q;
    crypto_bn dp;
    crypto_bn dq;
    crypto_bn qinv;
} rsa_private_key;

typedef struct {
    rsa_public_key pub;
    rsa_private_key priv;
} rsa_keypair;

typedef struct {
    uint8_t n[CRYPTO_BN_MAX_WORDS * 8];
    size_t n_len;
    uint8_t e[CRYPTO_BN_MAX_WORDS * 8];
    size_t e_len;
} rsa_public_key_bytes;

typedef struct {
    uint8_t n[CRYPTO_BN_MAX_WORDS * 8];
    size_t n_len;
    uint8_t d[CRYPTO_BN_MAX_WORDS * 8];
    size_t d_len;
    uint8_t p[CRYPTO_BN_MAX_WORDS * 8];
    size_t p_len;
    uint8_t q[CRYPTO_BN_MAX_WORDS * 8];
    size_t q_len;
    uint8_t dp[CRYPTO_BN_MAX_WORDS * 8];
    size_t dp_len;
    uint8_t dq[CRYPTO_BN_MAX_WORDS * 8];
    size_t dq_len;
    uint8_t qinv[CRYPTO_BN_MAX_WORDS * 8];
    size_t qinv_len;
} rsa_private_key_bytes;

int rsa_generate_key(rsa_keypair *keypair, size_t bits);
int rsa_public(const rsa_public_key *key, crypto_bn *out, const crypto_bn *in);
int rsa_private(const rsa_private_key *key, crypto_bn *out, const crypto_bn *in);
int rsa_public_key_to_bytes(const rsa_public_key *key, rsa_public_key_bytes *out);
int rsa_private_key_to_bytes(const rsa_private_key *key, rsa_private_key_bytes *out);
int rsa_public_bytes(const rsa_public_key_bytes *key, uint8_t *out, size_t out_len,
                     const uint8_t *in, size_t in_len);
int rsa_private_bytes(const rsa_private_key_bytes *key, uint8_t *out, size_t out_len,
                      const uint8_t *in, size_t in_len);

#ifdef __cplusplus
}
#endif

#endif
