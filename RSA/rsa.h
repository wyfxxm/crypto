#ifndef CRYPTO_RSA_H
#define CRYPTO_RSA_H

#include <stddef.h>

#include "../bn/crypto_bn.h"

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

int rsa_generate_key(rsa_keypair *keypair, size_t bits);
int rsa_public(const rsa_public_key *key, crypto_bn *out, const crypto_bn *in);
int rsa_private(const rsa_private_key *key, crypto_bn *out, const crypto_bn *in);

#ifdef __cplusplus
}
#endif

#endif
