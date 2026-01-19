#include "sm2_bn.h"

void sm2_bn_zero(sm2_bn *r) {
    for (int i = 0; i < SM2_BN_WORDS; ++i) {
        r->v[i] = 0;
    }
}

void sm2_bn_copy(sm2_bn *r, const sm2_bn *a) {
    for (int i = 0; i < SM2_BN_WORDS; ++i) {
        r->v[i] = a->v[i];
    }
}

int sm2_bn_is_zero(const sm2_bn *a) {
    for (int i = 0; i < SM2_BN_WORDS; ++i) {
        if (a->v[i] != 0) {
            return 0;
        }
    }
    return 1;
}

int sm2_bn_cmp(const sm2_bn *a, const sm2_bn *b) {
    for (int i = SM2_BN_WORDS - 1; i >= 0; --i) {
        if (a->v[i] > b->v[i]) {
            return 1;
        }
        if (a->v[i] < b->v[i]) {
            return -1;
        }
    }
    return 0;
}

void sm2_bn_from_bytes(sm2_bn *r, const uint8_t in[32]) {
    for (int i = 0; i < SM2_BN_WORDS; ++i) {
        int offset = (SM2_BN_WORDS - 1 - i) * 4;
        r->v[i] = ((uint32_t)in[offset] << 24)
            | ((uint32_t)in[offset + 1] << 16)
            | ((uint32_t)in[offset + 2] << 8)
            | (uint32_t)in[offset + 3];
    }
}

void sm2_bn_to_bytes(const sm2_bn *a, uint8_t out[32]) {
    for (int i = 0; i < SM2_BN_WORDS; ++i) {
        int offset = (SM2_BN_WORDS - 1 - i) * 4;
        out[offset] = (uint8_t)(a->v[i] >> 24);
        out[offset + 1] = (uint8_t)(a->v[i] >> 16);
        out[offset + 2] = (uint8_t)(a->v[i] >> 8);
        out[offset + 3] = (uint8_t)(a->v[i]);
    }
}

uint32_t sm2_bn_add(sm2_bn *r, const sm2_bn *a, const sm2_bn *b) {
    uint64_t carry = 0;
    for (int i = 0; i < SM2_BN_WORDS; ++i) {
        uint64_t sum = (uint64_t)a->v[i] + b->v[i] + carry;
        r->v[i] = (uint32_t)sum;
        carry = sum >> 32;
    }
    return (uint32_t)carry;
}

uint32_t sm2_bn_sub(sm2_bn *r, const sm2_bn *a, const sm2_bn *b) {
    uint64_t borrow = 0;
    for (int i = 0; i < SM2_BN_WORDS; ++i) {
        uint64_t av = a->v[i];
        uint64_t bv = b->v[i];
        uint64_t diff = av - bv - borrow;
        r->v[i] = (uint32_t)diff;
        borrow = (diff >> 63) & 0x1;
    }
    return (uint32_t)borrow;
}

void sm2_bn_add_mod(sm2_bn *r, const sm2_bn *a, const sm2_bn *b, const sm2_bn *mod) {
    sm2_bn tmp;
    uint32_t carry = sm2_bn_add(&tmp, a, b);
    if (carry || sm2_bn_cmp(&tmp, mod) >= 0) {
        sm2_bn_sub(&tmp, &tmp, mod);
    }
    sm2_bn_copy(r, &tmp);
}

void sm2_bn_sub_mod(sm2_bn *r, const sm2_bn *a, const sm2_bn *b, const sm2_bn *mod) {
    sm2_bn tmp;
    if (sm2_bn_sub(&tmp, a, b)) {
        sm2_bn_add(&tmp, &tmp, mod);
    }
    sm2_bn_copy(r, &tmp);
}

static int bn512_cmp(const sm2_bn512 *a, const sm2_bn512 *b) {
    for (int i = SM2_BN_WORDS * 2 - 1; i >= 0; --i) {
        if (a->v[i] > b->v[i]) {
            return 1;
        }
        if (a->v[i] < b->v[i]) {
            return -1;
        }
    }
    return 0;
}

static void bn512_sub(sm2_bn512 *r, const sm2_bn512 *a, const sm2_bn512 *b) {
    uint64_t borrow = 0;
    for (int i = 0; i < SM2_BN_WORDS * 2; ++i) {
        uint64_t av = a->v[i];
        uint64_t bv = b->v[i];
        uint64_t diff = av - bv - borrow;
        r->v[i] = (uint32_t)diff;
        borrow = (diff >> 63) & 0x1;
    }
}

static void bn512_copy(sm2_bn512 *r, const sm2_bn512 *a) {
    for (int i = 0; i < SM2_BN_WORDS * 2; ++i) {
        r->v[i] = a->v[i];
    }
}

static int bn512_bit_length(const sm2_bn512 *a) {
    for (int i = SM2_BN_WORDS * 2 - 1; i >= 0; --i) {
        if (a->v[i] != 0) {
            uint32_t v = a->v[i];
            int bits = 0;
            while (v) {
                v >>= 1;
                bits++;
            }
            return i * 32 + bits;
        }
    }
    return 0;
}

int sm2_bn_bit_length(const sm2_bn *a) {
    for (int i = SM2_BN_WORDS - 1; i >= 0; --i) {
        if (a->v[i] != 0) {
            uint32_t v = a->v[i];
            int bits = 0;
            while (v) {
                v >>= 1;
                bits++;
            }
            return i * 32 + bits;
        }
    }
    return 0;
}

static void bn_shift_left_512(sm2_bn512 *r, const sm2_bn *a, int shift) {
    for (int i = 0; i < SM2_BN_WORDS * 2; ++i) {
        r->v[i] = 0;
    }
    if (shift < 0) {
        return;
    }
    int word_shift = shift / 32;
    int bit_shift = shift % 32;
    for (int i = 0; i < SM2_BN_WORDS; ++i) {
        uint32_t v = a->v[i];
        int idx = i + word_shift;
        if (idx < SM2_BN_WORDS * 2) {
            r->v[idx] |= v << bit_shift;
        }
        if (bit_shift && idx + 1 < SM2_BN_WORDS * 2) {
            r->v[idx + 1] |= v >> (32 - bit_shift);
        }
    }
}

void sm2_bn_mul(sm2_bn512 *r, const sm2_bn *a, const sm2_bn *b) {
    for (int i = 0; i < SM2_BN_WORDS * 2; ++i) {
        r->v[i] = 0;
    }
    for (int i = 0; i < SM2_BN_WORDS; ++i) {
        uint64_t carry = 0;
        for (int j = 0; j < SM2_BN_WORDS; ++j) {
            uint64_t cur = r->v[i + j] + (uint64_t)a->v[i] * b->v[j] + carry;
            r->v[i + j] = (uint32_t)cur;
            carry = cur >> 32;
        }
        int idx = i + SM2_BN_WORDS;
        uint64_t sum = (uint64_t)r->v[idx] + carry;
        r->v[idx] = (uint32_t)sum;
        carry = sum >> 32;
        while (carry && ++idx < SM2_BN_WORDS * 2) {
            sum = (uint64_t)r->v[idx] + carry;
            r->v[idx] = (uint32_t)sum;
            carry = sum >> 32;
        }
    }
}

void sm2_bn_mod(sm2_bn *r, const sm2_bn512 *a, const sm2_bn *mod) {
    sm2_bn512 temp;
    bn512_copy(&temp, a);
    int mod_bits = sm2_bn_bit_length(mod);
    int temp_bits = bn512_bit_length(&temp);
    for (int shift = temp_bits - mod_bits; shift >= 0; --shift) {
        sm2_bn512 shifted;
        bn_shift_left_512(&shifted, mod, shift);
        if (bn512_cmp(&temp, &shifted) >= 0) {
            bn512_sub(&temp, &temp, &shifted);
        }
    }
    for (int i = 0; i < SM2_BN_WORDS; ++i) {
        r->v[i] = temp.v[i];
    }
    sm2_bn_mod_simple(r, r, mod);
}

void sm2_bn_mod_simple(sm2_bn *r, const sm2_bn *a, const sm2_bn *mod) {
    sm2_bn tmp;
    sm2_bn_copy(&tmp, a);
    while (sm2_bn_cmp(&tmp, mod) >= 0) {
        sm2_bn_sub(&tmp, &tmp, mod);
    }
    sm2_bn_copy(r, &tmp);
}

void sm2_bn_mod_mul(sm2_bn *r, const sm2_bn *a, const sm2_bn *b, const sm2_bn *mod) {
    sm2_bn512 product;
    sm2_bn_mul(&product, a, b);
    sm2_bn_mod(r, &product, mod);
}

int sm2_bn_get_bit(const sm2_bn *a, int bit) {
    if (bit < 0 || bit >= SM2_BN_WORDS * 32) {
        return 0;
    }
    int word = bit / 32;
    int offset = bit % 32;
    return (a->v[word] >> offset) & 0x1;
}

void sm2_bn_mod_exp(sm2_bn *r, const sm2_bn *a, const sm2_bn *exp, const sm2_bn *mod) {
    sm2_bn base;
    sm2_bn result;
    sm2_bn_zero(&result);
    result.v[0] = 1;
    sm2_bn_mod_simple(&base, a, mod);
    int bits = sm2_bn_bit_length(exp);
    for (int i = bits - 1; i >= 0; --i) {
        sm2_bn_mod_mul(&result, &result, &result, mod);
        if (sm2_bn_get_bit(exp, i)) {
            sm2_bn_mod_mul(&result, &result, &base, mod);
        }
    }
    sm2_bn_copy(r, &result);
}

void sm2_bn_mod_inv(sm2_bn *r, const sm2_bn *a, const sm2_bn *mod) {
    sm2_bn exp;
    sm2_bn_copy(&exp, mod);
    sm2_bn_sub_u32(&exp, &exp, 2, mod);
    sm2_bn_mod_exp(r, a, &exp, mod);
}

void sm2_bn_add_u32(sm2_bn *r, const sm2_bn *a, uint32_t v, const sm2_bn *mod) {
    sm2_bn tmp;
    sm2_bn_copy(&tmp, a);
    uint64_t sum = (uint64_t)tmp.v[0] + v;
    tmp.v[0] = (uint32_t)sum;
    uint64_t carry = sum >> 32;
    for (int i = 1; i < SM2_BN_WORDS && carry; ++i) {
        uint64_t cur = (uint64_t)tmp.v[i] + carry;
        tmp.v[i] = (uint32_t)cur;
        carry = cur >> 32;
    }
    sm2_bn_mod_simple(r, &tmp, mod);
}

void sm2_bn_sub_u32(sm2_bn *r, const sm2_bn *a, uint32_t v, const sm2_bn *mod) {
    sm2_bn tmp;
    sm2_bn_copy(&tmp, a);
    uint64_t diff = (uint64_t)tmp.v[0] - v;
    tmp.v[0] = (uint32_t)diff;
    uint64_t borrow = (diff >> 63) & 0x1;
    for (int i = 1; i < SM2_BN_WORDS && borrow; ++i) {
        uint64_t cur = (uint64_t)tmp.v[i] - borrow;
        tmp.v[i] = (uint32_t)cur;
        borrow = (cur >> 63) & 0x1;
    }
    if (borrow) {
        sm2_bn_add(&tmp, &tmp, mod);
    }
    sm2_bn_copy(r, &tmp);
}
