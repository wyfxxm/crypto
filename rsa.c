#include "rsa.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    int sign;
    crypto_bn mag;
} rsa_signed_bn;

static void rsa_bn_zero(crypto_bn *r) {
    crypto_bn_zero(r);
}

static void rsa_bn_from_u64(crypto_bn *r, uint64_t value) {
    crypto_bn_from_u64(r, value);
}

static void rsa_bn_add_u64(crypto_bn *r, const crypto_bn *a, uint64_t value) {
    crypto_bn tmp;
    crypto_bn_from_u64(&tmp, value);
    crypto_bn_add(r, a, &tmp);
}

static void rsa_bn_sub_u64(crypto_bn *r, const crypto_bn *a, uint64_t value) {
    crypto_bn tmp;
    crypto_bn_from_u64(&tmp, value);
    crypto_bn_sub(r, a, &tmp);
}

static int rsa_random_bytes(uint8_t *out, size_t len) {
    FILE *fp = fopen("/dev/urandom", "rb");
    if (fp) {
        size_t read_len = fread(out, 1, len, fp);
        fclose(fp);
        return read_len == len;
    }
    srand((unsigned)time(NULL));
    for (size_t i = 0; i < len; ++i) {
        out[i] = (uint8_t)(rand() & 0xFF);
    }
    return 1;
}

static void rsa_bn_shift_left(crypto_bn *r, const crypto_bn *a, size_t shift) {
    size_t word_shift = shift / 64;
    size_t bit_shift = shift % 64;
    for (size_t i = 0; i < CRYPTO_BN_MAX_WORDS; ++i) {
        r->v[i] = 0;
    }
    if (a->words == 0 || word_shift >= CRYPTO_BN_MAX_WORDS) {
        r->words = 0;
        return;
    }
    size_t max = a->words + word_shift + 1;
    if (max > CRYPTO_BN_MAX_WORDS) {
        max = CRYPTO_BN_MAX_WORDS;
    }
    for (size_t i = 0; i < a->words; ++i) {
        size_t idx = i + word_shift;
        if (idx < CRYPTO_BN_MAX_WORDS) {
            r->v[idx] |= a->v[i] << bit_shift;
        }
        if (bit_shift && idx + 1 < CRYPTO_BN_MAX_WORDS) {
            r->v[idx + 1] |= a->v[i] >> (64 - bit_shift);
        }
    }
    r->words = max;
    while (r->words > 0 && r->v[r->words - 1] == 0) {
        --r->words;
    }
}

static void rsa_bn_rshift1(crypto_bn *r) {
    uint64_t carry = 0;
    for (size_t i = r->words; i > 0; --i) {
        size_t idx = i - 1;
        uint64_t next_carry = r->v[idx] << 63;
        r->v[idx] = (r->v[idx] >> 1) | carry;
        carry = next_carry;
    }
    while (r->words > 0 && r->v[r->words - 1] == 0) {
        --r->words;
    }
}

static void rsa_bn_set_bit(crypto_bn *r, size_t bit) {
    size_t word = bit / 64;
    size_t offset = bit % 64;
    if (word >= CRYPTO_BN_MAX_WORDS) {
        return;
    }
    r->v[word] |= (uint64_t)1u << offset;
    if (word + 1 > r->words) {
        r->words = word + 1;
    }
}

static int rsa_bn_divmod(crypto_bn *q, crypto_bn *r, const crypto_bn *a, const crypto_bn *b) {
    if (b->words == 0) {
        return 0;
    }
    crypto_bn temp;
    crypto_bn_copy(&temp, a);
    rsa_bn_zero(q);
    if (crypto_bn_cmp(&temp, b) < 0) {
        crypto_bn_copy(r, &temp);
        return 1;
    }
    size_t mod_bits = crypto_bn_bit_length(b);
    while (crypto_bn_cmp(&temp, b) >= 0) {
        size_t temp_bits = crypto_bn_bit_length(&temp);
        if (temp_bits < mod_bits) {
            break;
        }
        size_t shift = temp_bits - mod_bits;
        crypto_bn shifted;
        rsa_bn_shift_left(&shifted, b, shift);
        if (crypto_bn_cmp(&temp, &shifted) < 0 && shift > 0) {
            rsa_bn_shift_left(&shifted, b, shift - 1);
            shift -= 1;
        }
        crypto_bn_sub(&temp, &temp, &shifted);
        rsa_bn_set_bit(q, shift);
    }
    crypto_bn_copy(r, &temp);
    return 1;
}

static void rsa_signed_zero(rsa_signed_bn *r) {
    r->sign = 0;
    crypto_bn_zero(&r->mag);
}

static void rsa_signed_from_bn(rsa_signed_bn *r, const crypto_bn *a) {
    if (crypto_bn_is_zero(a)) {
        r->sign = 0;
    } else {
        r->sign = 1;
    }
    crypto_bn_copy(&r->mag, a);
}

static void rsa_signed_copy(rsa_signed_bn *r, const rsa_signed_bn *a) {
    r->sign = a->sign;
    crypto_bn_copy(&r->mag, &a->mag);
}

static void rsa_signed_neg(rsa_signed_bn *r) {
    if (r->sign != 0) {
        r->sign = -r->sign;
    }
}

static void rsa_signed_add(rsa_signed_bn *r, const rsa_signed_bn *a, const rsa_signed_bn *b) {
    if (a->sign == 0) {
        rsa_signed_copy(r, b);
        return;
    }
    if (b->sign == 0) {
        rsa_signed_copy(r, a);
        return;
    }
    if (a->sign == b->sign) {
        crypto_bn_add(&r->mag, &a->mag, &b->mag);
        r->sign = a->sign;
        return;
    }
    int cmp = crypto_bn_cmp(&a->mag, &b->mag);
    if (cmp == 0) {
        rsa_signed_zero(r);
        return;
    }
    if (cmp > 0) {
        crypto_bn_sub(&r->mag, &a->mag, &b->mag);
        r->sign = a->sign;
    } else {
        crypto_bn_sub(&r->mag, &b->mag, &a->mag);
        r->sign = b->sign;
    }
}

static void rsa_signed_sub(rsa_signed_bn *r, const rsa_signed_bn *a, const rsa_signed_bn *b) {
    rsa_signed_bn neg_b;
    rsa_signed_copy(&neg_b, b);
    rsa_signed_neg(&neg_b);
    rsa_signed_add(r, a, &neg_b);
}

static void rsa_signed_mul_bn(rsa_signed_bn *r, const rsa_signed_bn *a, const crypto_bn *b) {
    if (a->sign == 0 || crypto_bn_is_zero(b)) {
        rsa_signed_zero(r);
        return;
    }
    crypto_bn_mul(&r->mag, &a->mag, b);
    r->sign = a->sign;
}

static void rsa_signed_mod(const rsa_signed_bn *a, const crypto_bn *mod, crypto_bn *out) {
    crypto_bn tmp;
    crypto_bn_mod(&tmp, &a->mag, mod);
    if (a->sign >= 0) {
        crypto_bn_copy(out, &tmp);
        return;
    }
    if (crypto_bn_is_zero(&tmp)) {
        crypto_bn_zero(out);
        return;
    }
    crypto_bn_sub(out, mod, &tmp);
}

static int rsa_bn_gcd(crypto_bn *out, const crypto_bn *a, const crypto_bn *b) {
    crypto_bn x;
    crypto_bn y;
    crypto_bn_copy(&x, a);
    crypto_bn_copy(&y, b);
    while (!crypto_bn_is_zero(&y)) {
        crypto_bn r;
        if (!crypto_bn_mod(&r, &x, &y)) {
            return 0;
        }
        crypto_bn_copy(&x, &y);
        crypto_bn_copy(&y, &r);
    }
    crypto_bn_copy(out, &x);
    return 1;
}

static int rsa_bn_mod_inv(crypto_bn *out, const crypto_bn *a, const crypto_bn *mod) {
    rsa_signed_bn old_s;
    rsa_signed_bn s;
    rsa_signed_bn old_t;
    rsa_signed_bn t;
    crypto_bn old_r;
    crypto_bn r;

    crypto_bn_copy(&old_r, mod);
    crypto_bn_copy(&r, a);

    crypto_bn one;
    rsa_bn_from_u64(&one, 1);
    rsa_signed_from_bn(&old_s, &one);
    rsa_signed_zero(&s);
    rsa_signed_zero(&old_t);
    rsa_signed_from_bn(&t, &one);

    while (!crypto_bn_is_zero(&r)) {
        crypto_bn q;
        crypto_bn rem;
        if (!rsa_bn_divmod(&q, &rem, &old_r, &r)) {
            return 0;
        }
        crypto_bn_copy(&old_r, &r);
        crypto_bn_copy(&r, &rem);

        rsa_signed_bn q_s;
        rsa_signed_mul_bn(&q_s, &s, &q);
        rsa_signed_bn new_s;
        rsa_signed_sub(&new_s, &old_s, &q_s);
        rsa_signed_copy(&old_s, &s);
        rsa_signed_copy(&s, &new_s);

        rsa_signed_bn q_t;
        rsa_signed_mul_bn(&q_t, &t, &q);
        rsa_signed_bn new_t;
        rsa_signed_sub(&new_t, &old_t, &q_t);
        rsa_signed_copy(&old_t, &t);
        rsa_signed_copy(&t, &new_t);
    }

    crypto_bn gcd;
    crypto_bn_copy(&gcd, &old_r);
    crypto_bn gcd_one;
    rsa_bn_from_u64(&gcd_one, 1);
    if (crypto_bn_cmp(&gcd, &gcd_one) != 0) {
        return 0;
    }

    rsa_signed_mod(&old_t, mod, out);
    return 1;
}

static void rsa_bn_random_bits(crypto_bn *r, size_t bits) {
    size_t bytes = (bits + 7) / 8;
    uint8_t buf[CRYPTO_BN_MAX_WORDS * 8];
    if (bytes > sizeof(buf)) {
        bytes = sizeof(buf);
    }
    rsa_random_bytes(buf, bytes);
    if (bits > 0) {
        size_t top_bit = (bits - 1) % 8;
        buf[0] |= (uint8_t)(1u << top_bit);
    }
    buf[bytes - 1] |= 1u;
    crypto_bn_from_bytes(r, buf, bytes);
}

static int rsa_is_probable_prime(const crypto_bn *n, int rounds) {
    crypto_bn two;
    rsa_bn_from_u64(&two, 2);
    if (crypto_bn_cmp(n, &two) < 0) {
        return 0;
    }
    if (n->words == 1 && n->v[0] <= 3) {
        return 1;
    }
    if ((n->v[0] & 1u) == 0) {
        return 0;
    }

    static const uint32_t small_primes[] = {
        3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37
    };
    for (size_t i = 0; i < sizeof(small_primes) / sizeof(small_primes[0]); ++i) {
        crypto_bn p;
        rsa_bn_from_u64(&p, small_primes[i]);
        if (crypto_bn_cmp(n, &p) == 0) {
            return 1;
        }
        crypto_bn rem;
        crypto_bn_mod(&rem, n, &p);
        if (crypto_bn_is_zero(&rem)) {
            return 0;
        }
    }

    crypto_bn n_minus_one;
    rsa_bn_sub_u64(&n_minus_one, n, 1);

    crypto_bn d;
    crypto_bn_copy(&d, &n_minus_one);
    size_t s = 0;
    while (crypto_bn_get_bit(&d, 0) == 0) {
        rsa_bn_rshift1(&d);
        ++s;
    }

    size_t n_bits = crypto_bn_bit_length(n);
    crypto_bn n_minus_three;
    rsa_bn_sub_u64(&n_minus_three, n, 3);

    for (int i = 0; i < rounds; ++i) {
        crypto_bn a;
        rsa_bn_random_bits(&a, n_bits);
        crypto_bn_mod(&a, &a, &n_minus_three);
        rsa_bn_add_u64(&a, &a, 2);

        crypto_bn x;
        if (!crypto_bn_mod_exp(&x, &a, &d, n)) {
            return 0;
        }
        crypto_bn one;
        rsa_bn_from_u64(&one, 1);
        if (crypto_bn_cmp(&x, &one) == 0 || crypto_bn_cmp(&x, &n_minus_one) == 0) {
            continue;
        }
        int composite = 1;
        for (size_t r = 1; r < s; ++r) {
            if (!crypto_bn_mod_mul(&x, &x, &x, n)) {
                return 0;
            }
            if (crypto_bn_cmp(&x, &n_minus_one) == 0) {
                composite = 0;
                break;
            }
        }
        if (composite) {
            return 0;
        }
    }

    return 1;
}

static int rsa_generate_prime(crypto_bn *prime, size_t bits) {
    if (bits < 16) {
        return 0;
    }
    for (;;) {
        rsa_bn_random_bits(prime, bits);
        if (rsa_is_probable_prime(prime, 8)) {
            return 1;
        }
    }
}

int rsa_generate_key(rsa_keypair *keypair, size_t bits) {
    if (!keypair || bits < 64 || bits > CRYPTO_BN_MAX_WORDS * 64) {
        return 0;
    }
    size_t half = bits / 2;
    crypto_bn p;
    crypto_bn q;
    crypto_bn n;
    crypto_bn phi;
    crypto_bn p_minus_one;
    crypto_bn q_minus_one;
    crypto_bn e;
    rsa_bn_from_u64(&e, 65537);

    for (;;) {
        if (!rsa_generate_prime(&p, half)) {
            return 0;
        }
        if (!rsa_generate_prime(&q, bits - half)) {
            return 0;
        }
        if (crypto_bn_cmp(&p, &q) == 0) {
            continue;
        }
        if (!crypto_bn_mul(&n, &p, &q)) {
            return 0;
        }

        rsa_bn_sub_u64(&p_minus_one, &p, 1);
        rsa_bn_sub_u64(&q_minus_one, &q, 1);
        if (!crypto_bn_mul(&phi, &p_minus_one, &q_minus_one)) {
            return 0;
        }

        crypto_bn gcd;
        if (!rsa_bn_gcd(&gcd, &e, &phi)) {
            return 0;
        }
        crypto_bn one;
        rsa_bn_from_u64(&one, 1);
        if (crypto_bn_cmp(&gcd, &one) != 0) {
            continue;
        }

        crypto_bn d;
        if (!rsa_bn_mod_inv(&d, &e, &phi)) {
            continue;
        }

        crypto_bn dp;
        crypto_bn dq;
        crypto_bn qinv;
        if (!crypto_bn_mod(&dp, &d, &p_minus_one)) {
            return 0;
        }
        if (!crypto_bn_mod(&dq, &d, &q_minus_one)) {
            return 0;
        }
        if (!rsa_bn_mod_inv(&qinv, &q, &p)) {
            continue;
        }

        crypto_bn_copy(&keypair->pub.n, &n);
        crypto_bn_copy(&keypair->pub.e, &e);
        crypto_bn_copy(&keypair->priv.n, &n);
        crypto_bn_copy(&keypair->priv.d, &d);
        crypto_bn_copy(&keypair->priv.p, &p);
        crypto_bn_copy(&keypair->priv.q, &q);
        crypto_bn_copy(&keypair->priv.dp, &dp);
        crypto_bn_copy(&keypair->priv.dq, &dq);
        crypto_bn_copy(&keypair->priv.qinv, &qinv);
        return 1;
    }
}

int rsa_public(const rsa_public_key *key, crypto_bn *out, const crypto_bn *in) {
    if (!key || !out || !in) {
        return 0;
    }
    crypto_bn base;
    crypto_bn_mod(&base, in, &key->n);
    return crypto_bn_mod_exp(out, &base, &key->e, &key->n);
}

int rsa_private(const rsa_private_key *key, crypto_bn *out, const crypto_bn *in) {
    if (!key || !out || !in) {
        return 0;
    }
    crypto_bn base;
    crypto_bn_mod(&base, in, &key->n);
    crypto_bn m1;
    crypto_bn m2;
    if (!crypto_bn_mod_exp(&m1, &base, &key->dp, &key->p)) {
        return 0;
    }
    if (!crypto_bn_mod_exp(&m2, &base, &key->dq, &key->q)) {
        return 0;
    }

    crypto_bn diff;
    if (crypto_bn_cmp(&m1, &m2) >= 0) {
        crypto_bn_sub(&diff, &m1, &m2);
    } else {
        crypto_bn tmp;
        crypto_bn_sub(&tmp, &m2, &m1);
        crypto_bn_sub(&diff, &key->p, &tmp);
    }

    crypto_bn h;
    if (!crypto_bn_mod_mul(&h, &key->qinv, &diff, &key->p)) {
        return 0;
    }

    crypto_bn hq;
    if (!crypto_bn_mul(&hq, &h, &key->q)) {
        return 0;
    }
    crypto_bn_add(out, &m2, &hq);
    return 1;
}
