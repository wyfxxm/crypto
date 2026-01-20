#include "sm2.h"
#include "sm3.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static int sm2_params_initialized = 0;
static sm2_bn SM2_P;
static sm2_bn SM2_A;
static sm2_bn SM2_B;
static sm2_bn SM2_N;
static sm2_bn SM2_N_MINUS_1;
static sm2_point SM2_G;

static const uint8_t SM2_P_BYTES[32] = {
    0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
};

static const uint8_t SM2_A_BYTES[32] = {
    0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFC
};

static const uint8_t SM2_B_BYTES[32] = {
    0x28,0xE9,0xFA,0x9E,0x9D,0x9F,0x5E,0x34,
    0x4D,0x5A,0x9E,0x4B,0xCF,0x65,0x09,0xA7,
    0xF3,0x97,0x89,0xF5,0x15,0xAB,0x8F,0x92,
    0xDD,0xBC,0xBD,0x41,0x4D,0x94,0x0E,0x93
};

static const uint8_t SM2_N_BYTES[32] = {
    0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0x72,0x03,0xDF,0x6B,0x21,0xC6,0x05,0x2B,
    0x53,0xBB,0xF4,0x09,0x39,0xD5,0x41,0x23
};

static const uint8_t SM2_GX_BYTES[32] = {
    0x32,0xC4,0xAE,0x2C,0x1F,0x19,0x81,0x19,
    0x5F,0x99,0x04,0x46,0x6A,0x39,0xC9,0x94,
    0x8F,0xE3,0x0B,0xBF,0xF2,0x66,0x0B,0xE1,
    0x71,0x5A,0x45,0x89,0x33,0x4C,0x74,0xC7
};

static const uint8_t SM2_GY_BYTES[32] = {
    0xBC,0x37,0x36,0xA2,0xF4,0xF6,0x77,0x9C,
    0x59,0xBD,0xCE,0xE3,0x6B,0x69,0x21,0x53,
    0xD0,0xA9,0x87,0x7C,0xC6,0x2A,0x47,0x40,
    0x02,0xDF,0x32,0xE5,0x21,0x39,0xF0,0xA0
};

static void sm2_init_params(void) {
    if (sm2_params_initialized) {
        return;
    }
    sm2_bn_from_bytes(&SM2_P, SM2_P_BYTES);
    sm2_bn_from_bytes(&SM2_A, SM2_A_BYTES);
    sm2_bn_from_bytes(&SM2_B, SM2_B_BYTES);
    sm2_bn_from_bytes(&SM2_N, SM2_N_BYTES);
    sm2_bn_from_bytes(&SM2_G.x, SM2_GX_BYTES);
    sm2_bn_from_bytes(&SM2_G.y, SM2_GY_BYTES);
    SM2_G.infinity = 0;
    sm2_bn_sub_u32(&SM2_N_MINUS_1, &SM2_N, 1, &SM2_N);
    sm2_params_initialized = 1;
}

static void sm2_point_set_infinity(sm2_point *p) {
    sm2_bn_zero(&p->x);
    sm2_bn_zero(&p->y);
    p->infinity = 1;
}

static void sm2_point_copy(sm2_point *r, const sm2_point *p) {
    sm2_bn_copy(&r->x, &p->x);
    sm2_bn_copy(&r->y, &p->y);
    r->infinity = p->infinity;
}

static int sm2_point_is_infinity(const sm2_point *p) {
    return p->infinity;
}

static void sm2_point_cswap(sm2_point *a, sm2_point *b, uint32_t swap) {
    uint64_t mask = 0u - (uint64_t)swap;
    for (size_t i = 0; i < CRYPTO_BN_MAX_WORDS; ++i) {
        uint64_t t = mask & (a->x.v[i] ^ b->x.v[i]);
        a->x.v[i] ^= t;
        b->x.v[i] ^= t;
        t = mask & (a->y.v[i] ^ b->y.v[i]);
        a->y.v[i] ^= t;
        b->y.v[i] ^= t;
    }
    size_t mask_words = (size_t)mask;
    size_t t_words = mask_words & (a->x.words ^ b->x.words);
    a->x.words ^= t_words;
    b->x.words ^= t_words;
    t_words = mask_words & (a->y.words ^ b->y.words);
    a->y.words ^= t_words;
    b->y.words ^= t_words;
    int t_inf = (int)(mask & (uint64_t)(a->infinity ^ b->infinity));
    a->infinity ^= t_inf;
    b->infinity ^= t_inf;
}

static int sm2_point_is_on_curve(const sm2_point *p) {
    if (sm2_point_is_infinity(p)) {
        return 0;
    }
    sm2_bn y2;
    sm2_bn x2;
    sm2_bn x3;
    sm2_bn ax;
    sm2_bn rhs;
    sm2_bn_mod_mul(&y2, &p->y, &p->y, &SM2_P);
    sm2_bn_mod_mul(&x2, &p->x, &p->x, &SM2_P);
    sm2_bn_mod_mul(&x3, &x2, &p->x, &SM2_P);
    sm2_bn_mod_mul(&ax, &SM2_A, &p->x, &SM2_P);
    sm2_bn_add_mod(&rhs, &x3, &ax, &SM2_P);
    sm2_bn_add_mod(&rhs, &rhs, &SM2_B, &SM2_P);
    return sm2_bn_cmp(&y2, &rhs) == 0;
}

static int sm2_point_is_valid(const sm2_point *p) {
    if (!sm2_point_is_on_curve(p)) {
        return 0;
    }
    sm2_point check;
    sm2_point_mul(&check, p, &SM2_N);
    return sm2_point_is_infinity(&check);
}

static void sm2_point_double(sm2_point *r, const sm2_point *p) {
    if (sm2_point_is_infinity(p) || sm2_bn_is_zero(&p->y)) {
        sm2_point_set_infinity(r);
        return;
    }
    sm2_bn lambda;
    sm2_bn x2;
    sm2_bn three_x2;
    sm2_bn numerator;
    sm2_bn denominator;
    sm2_bn inv_denominator;

    sm2_bn_mod_mul(&x2, &p->x, &p->x, &SM2_P);
    sm2_bn_add_mod(&three_x2, &x2, &x2, &SM2_P);
    sm2_bn_add_mod(&three_x2, &three_x2, &x2, &SM2_P);
    sm2_bn_add_mod(&numerator, &three_x2, &SM2_A, &SM2_P);

    sm2_bn_add_mod(&denominator, &p->y, &p->y, &SM2_P);
    sm2_bn_mod_inv(&inv_denominator, &denominator, &SM2_P);
    sm2_bn_mod_mul(&lambda, &numerator, &inv_denominator, &SM2_P);

    sm2_bn lambda_sq;
    sm2_bn_mod_mul(&lambda_sq, &lambda, &lambda, &SM2_P);

    sm2_bn two_x;
    sm2_bn_add_mod(&two_x, &p->x, &p->x, &SM2_P);
    sm2_bn_sub_mod(&r->x, &lambda_sq, &two_x, &SM2_P);

    sm2_bn x_minus_x3;
    sm2_bn_sub_mod(&x_minus_x3, &p->x, &r->x, &SM2_P);
    sm2_bn_mod_mul(&r->y, &lambda, &x_minus_x3, &SM2_P);
    sm2_bn_sub_mod(&r->y, &r->y, &p->y, &SM2_P);
    r->infinity = 0;
}

static void sm2_point_add(sm2_point *r, const sm2_point *p, const sm2_point *q) {
    if (sm2_point_is_infinity(p)) {
        sm2_point_copy(r, q);
        return;
    }
    if (sm2_point_is_infinity(q)) {
        sm2_point_copy(r, p);
        return;
    }
    if (sm2_bn_cmp(&p->x, &q->x) == 0) {
        if (sm2_bn_cmp(&p->y, &q->y) == 0) {
            sm2_point_double(r, p);
        } else {
            sm2_point_set_infinity(r);
        }
        return;
    }

    sm2_bn lambda;
    sm2_bn numerator;
    sm2_bn denominator;
    sm2_bn inv_denominator;

    sm2_bn_sub_mod(&numerator, &q->y, &p->y, &SM2_P);
    sm2_bn_sub_mod(&denominator, &q->x, &p->x, &SM2_P);
    sm2_bn_mod_inv(&inv_denominator, &denominator, &SM2_P);
    sm2_bn_mod_mul(&lambda, &numerator, &inv_denominator, &SM2_P);

    sm2_bn lambda_sq;
    sm2_bn_mod_mul(&lambda_sq, &lambda, &lambda, &SM2_P);
    sm2_bn_sub_mod(&r->x, &lambda_sq, &p->x, &SM2_P);
    sm2_bn_sub_mod(&r->x, &r->x, &q->x, &SM2_P);

    sm2_bn x_minus_x3;
    sm2_bn_sub_mod(&x_minus_x3, &p->x, &r->x, &SM2_P);
    sm2_bn_mod_mul(&r->y, &lambda, &x_minus_x3, &SM2_P);
    sm2_bn_sub_mod(&r->y, &r->y, &p->y, &SM2_P);
    r->infinity = 0;
}

static void sm2_point_mul(sm2_point *r, const sm2_point *p, const sm2_bn *k) {
    sm2_point r0;
    sm2_point r1;
    sm2_point_set_infinity(&r0);
    sm2_point_copy(&r1, p);
    for (int i = (SM2_BN_BYTES * 8) - 1; i >= 0; --i) {
        uint32_t bit = (uint32_t)sm2_bn_get_bit(k, i);
        sm2_point_cswap(&r0, &r1, bit);
        sm2_point_add(&r0, &r0, &r1);
        sm2_point_double(&r1, &r1);
        sm2_point_cswap(&r0, &r1, bit);
    }
    sm2_point_copy(r, &r0);
}

static int sm2_random_bytes(uint8_t *out, size_t len) {
    FILE *fp = fopen("/dev/urandom", "rb");
    if (fp) {
        size_t read_len = fread(out, 1, len, fp);
        fclose(fp);
        return read_len == len;
    }
    return 0;
}

static int sm2_bn_random_range(sm2_bn *r, const sm2_bn *max) {
    uint8_t buf[32];
    if (!sm2_random_bytes(buf, sizeof(buf))) {
        return 0;
    }
    sm2_bn_from_bytes(r, buf);
    sm2_bn_mod_simple(r, r, max);
    sm2_bn_add_u32(r, r, 1, max);
    return 1;
}

static void sm2_kdf(uint8_t *out, size_t out_len, const uint8_t *z, size_t z_len) {
    uint32_t ct = 1;
    size_t offset = 0;
    uint8_t hash[32];
    uint8_t buffer[64 + 4];
    while (offset < out_len) {
        memcpy(buffer, z, z_len);
        buffer[z_len] = (uint8_t)(ct >> 24);
        buffer[z_len + 1] = (uint8_t)(ct >> 16);
        buffer[z_len + 2] = (uint8_t)(ct >> 8);
        buffer[z_len + 3] = (uint8_t)(ct);
        sm3_hash(buffer, z_len + 4, hash);
        size_t chunk = out_len - offset;
        if (chunk > 32) {
            chunk = 32;
        }
        memcpy(out + offset, hash, chunk);
        offset += chunk;
        ct++;
    }
}

static int sm2_kdf_nonzero(uint8_t *out, size_t out_len, const uint8_t *z, size_t z_len) {
    sm2_kdf(out, out_len, z, z_len);
    for (size_t i = 0; i < out_len; ++i) {
        if (out[i] != 0) {
            return 1;
        }
    }
    return 0;
}

int sm2_generate_key(sm2_key *key) {
    if (!key) {
        return 0;
    }
    sm2_init_params();
    if (!sm2_bn_random_range(&key->d, &SM2_N_MINUS_1)) {
        return 0;
    }
    sm2_point_mul(&key->public_key, &SM2_G, &key->d);
    return 1;
}

int sm2_sign(const sm2_key *key, const uint8_t e[32], uint8_t r[32], uint8_t s[32]) {
    if (!key || !e || !r || !s) {
        return 0;
    }
    sm2_init_params();
    if (!sm2_point_is_valid(&key->public_key)) {
        return 0;
    }
    sm2_bn e_bn;
    sm2_bn_from_bytes(&e_bn, e);

    while (1) {
        sm2_bn k;
        if (!sm2_bn_random_range(&k, &SM2_N_MINUS_1)) {
            return 0;
        }
        sm2_point p1;
        sm2_point_mul(&p1, &SM2_G, &k);
        sm2_bn r_bn;
        sm2_bn_add_mod(&r_bn, &e_bn, &p1.x, &SM2_N);
        if (sm2_bn_is_zero(&r_bn)) {
            continue;
        }
        sm2_bn rk;
        sm2_bn_add(&rk, &r_bn, &k);
        if (sm2_bn_cmp(&rk, &SM2_N) == 0) {
            continue;
        }
        sm2_bn one_plus_d;
        sm2_bn_add_u32(&one_plus_d, &key->d, 1, &SM2_N);
        sm2_bn inv;
        sm2_bn_mod_inv(&inv, &one_plus_d, &SM2_N);
        sm2_bn rd;
        sm2_bn_mod_mul(&rd, &r_bn, &key->d, &SM2_N);
        sm2_bn k_minus_rd;
        sm2_bn_sub_mod(&k_minus_rd, &k, &rd, &SM2_N);
        sm2_bn s_bn;
        sm2_bn_mod_mul(&s_bn, &inv, &k_minus_rd, &SM2_N);
        if (sm2_bn_is_zero(&s_bn)) {
            continue;
        }
        sm2_bn_to_bytes(&r_bn, r);
        sm2_bn_to_bytes(&s_bn, s);
        return 1;
    }
}

int sm2_verify(const sm2_point *pub, const uint8_t e[32], const uint8_t r[32], const uint8_t s[32]) {
    if (!pub || !e || !r || !s) {
        return 0;
    }
    sm2_init_params();
    if (!sm2_point_is_valid(pub)) {
        return 0;
    }
    sm2_bn r_bn;
    sm2_bn s_bn;
    sm2_bn e_bn;
    sm2_bn_from_bytes(&r_bn, r);
    sm2_bn_from_bytes(&s_bn, s);
    sm2_bn_from_bytes(&e_bn, e);
    if (sm2_bn_is_zero(&r_bn) || sm2_bn_is_zero(&s_bn)) {
        return 0;
    }
    if (sm2_bn_cmp(&r_bn, &SM2_N) >= 0 || sm2_bn_cmp(&s_bn, &SM2_N) >= 0) {
        return 0;
    }
    sm2_bn t;
    sm2_bn_add_mod(&t, &r_bn, &s_bn, &SM2_N);
    if (sm2_bn_is_zero(&t)) {
        return 0;
    }
    sm2_point sG;
    sm2_point tP;
    sm2_point_mul(&sG, &SM2_G, &s_bn);
    sm2_point_mul(&tP, pub, &t);
    sm2_point sum;
    sm2_point_add(&sum, &sG, &tP);
    if (sm2_point_is_infinity(&sum)) {
        return 0;
    }
    sm2_bn R;
    sm2_bn_add_mod(&R, &e_bn, &sum.x, &SM2_N);
    return sm2_bn_cmp(&R, &r_bn) == 0;
}

int sm2_encrypt(const sm2_point *pub, const uint8_t *msg, size_t msg_len, uint8_t **out, size_t *out_len) {
    if (!pub || !msg || !out || !out_len) {
        return 0;
    }
    sm2_init_params();
    if (!sm2_point_is_valid(pub)) {
        return 0;
    }
    size_t total_len = 65 + 32 + msg_len;
    while (1) {
        uint8_t *buf = (uint8_t *)malloc(total_len);
        if (!buf) {
            return 0;
        }
        uint8_t *c1 = buf;
        uint8_t *c3 = buf + 65;
        uint8_t *c2 = buf + 65 + 32;

        sm2_bn k;
        if (!sm2_bn_random_range(&k, &SM2_N_MINUS_1)) {
            free(buf);
            return 0;
        }
        sm2_point c1_point;
        sm2_point_mul(&c1_point, &SM2_G, &k);
        sm2_point s;
        sm2_point_mul(&s, pub, &k);

        uint8_t x2[32];
        uint8_t y2[32];
        sm2_bn_to_bytes(&s.x, x2);
        sm2_bn_to_bytes(&s.y, y2);

        uint8_t *t = (uint8_t *)malloc(msg_len);
        if (!t) {
            free(buf);
            return 0;
        }
        uint8_t z[64];
        memcpy(z, x2, 32);
        memcpy(z + 32, y2, 32);
        if (!sm2_kdf_nonzero(t, msg_len, z, sizeof(z))) {
            free(t);
            free(buf);
            continue;
        }
        for (size_t i = 0; i < msg_len; ++i) {
            c2[i] = msg[i] ^ t[i];
        }
        free(t);

        uint8_t *hash_input = (uint8_t *)malloc(64 + msg_len);
        if (!hash_input) {
            free(buf);
            return 0;
        }
        memcpy(hash_input, x2, 32);
        memcpy(hash_input + 32, msg, msg_len);
        memcpy(hash_input + 32 + msg_len, y2, 32);
        sm3_hash(hash_input, 64 + msg_len, c3);
        free(hash_input);

        c1[0] = 0x04;
        sm2_bn_to_bytes(&c1_point.x, c1 + 1);
        sm2_bn_to_bytes(&c1_point.y, c1 + 33);
        *out = buf;
        *out_len = total_len;
        return 1;
    }
}

int sm2_decrypt(const sm2_key *key, const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len) {
    if (!key || !in || !out || !out_len) {
        return 0;
    }
    sm2_init_params();
    if (in_len < 97 || in[0] != 0x04) {
        return 0;
    }
    size_t msg_len = in_len - 97;
    const uint8_t *c1 = in;
    const uint8_t *c3 = in + 65;
    const uint8_t *c2 = in + 97;

    sm2_point c1_point;
    sm2_bn_from_bytes(&c1_point.x, c1 + 1);
    sm2_bn_from_bytes(&c1_point.y, c1 + 33);
    c1_point.infinity = 0;
    if (!sm2_point_is_valid(&c1_point)) {
        return 0;
    }

    sm2_point s;
    sm2_point_mul(&s, &c1_point, &key->d);
    uint8_t x2[32];
    uint8_t y2[32];
    sm2_bn_to_bytes(&s.x, x2);
    sm2_bn_to_bytes(&s.y, y2);

    uint8_t *t = (uint8_t *)malloc(msg_len);
    if (!t) {
        return 0;
    }
    uint8_t z[64];
    memcpy(z, x2, 32);
    memcpy(z + 32, y2, 32);
    if (!sm2_kdf_nonzero(t, msg_len, z, sizeof(z))) {
        free(t);
        return 0;
    }

    uint8_t *msg = (uint8_t *)malloc(msg_len);
    if (!msg) {
        free(t);
        return 0;
    }
    for (size_t i = 0; i < msg_len; ++i) {
        msg[i] = c2[i] ^ t[i];
    }
    free(t);

    uint8_t *hash_input = (uint8_t *)malloc(64 + msg_len);
    if (!hash_input) {
        free(msg);
        return 0;
    }
    memcpy(hash_input, x2, 32);
    memcpy(hash_input + 32, msg, msg_len);
    memcpy(hash_input + 32 + msg_len, y2, 32);
    uint8_t u[32];
    sm3_hash(hash_input, 64 + msg_len, u);
    free(hash_input);
    if (memcmp(u, c3, 32) != 0) {
        free(msg);
        return 0;
    }
    *out = msg;
    *out_len = msg_len;
    return 1;
}
