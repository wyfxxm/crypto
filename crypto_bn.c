#include "crypto_bn.h"

static void crypto_bn_normalize(crypto_bn *r) {
    size_t i = r->words;
    while (i > 0 && r->v[i - 1] == 0) {
        --i;
    }
    r->words = i;
}

static int crypto_bn_is_even(const crypto_bn *a) {
    return a->words == 0 || (a->v[0] & 1u) == 0;
}

static void crypto_bn_rshift1(crypto_bn *r) {
    uint64_t carry = 0;
    for (size_t i = r->words; i > 0; --i) {
        size_t idx = i - 1;
        uint64_t next_carry = r->v[idx] << 63;
        r->v[idx] = (r->v[idx] >> 1) | carry;
        carry = next_carry;
    }
    crypto_bn_normalize(r);
}

void crypto_bn_zero(crypto_bn *r) {
    for (size_t i = 0; i < CRYPTO_BN_MAX_WORDS; ++i) {
        r->v[i] = 0;
    }
    r->words = 0;
}

void crypto_bn_copy(crypto_bn *r, const crypto_bn *a) {
    for (size_t i = 0; i < CRYPTO_BN_MAX_WORDS; ++i) {
        r->v[i] = a->v[i];
    }
    r->words = a->words;
}

int crypto_bn_is_zero(const crypto_bn *a) {
    return a->words == 0;
}

int crypto_bn_cmp(const crypto_bn *a, const crypto_bn *b) {
    if (a->words > b->words) {
        return 1;
    }
    if (a->words < b->words) {
        return -1;
    }
    for (size_t i = a->words; i > 0; --i) {
        size_t idx = i - 1;
        if (a->v[idx] > b->v[idx]) {
            return 1;
        }
        if (a->v[idx] < b->v[idx]) {
            return -1;
        }
    }
    return 0;
}

int crypto_bn_from_bytes(crypto_bn *r, const uint8_t *in, size_t len) {
    size_t words = (len + 7) / 8;
    if (words > CRYPTO_BN_MAX_WORDS) {
        return 0;
    }
    crypto_bn_zero(r);
    for (size_t i = 0; i < len; ++i) {
        size_t byte_index = len - 1 - i;
        size_t word_index = i / 8;
        size_t shift = (i % 8) * 8;
        r->v[word_index] |= ((uint64_t)in[byte_index]) << shift;
    }
    r->words = words;
    crypto_bn_normalize(r);
    return 1;
}

void crypto_bn_to_bytes(const crypto_bn *a, uint8_t *out, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        out[i] = 0;
    }
    for (size_t i = 0; i < a->words; ++i) {
        uint64_t value = a->v[i];
        for (size_t j = 0; j < 8; ++j) {
            size_t idx = len - 1 - (i * 8 + j);
            if (idx < len) {
                out[idx] = (uint8_t)(value & 0xffu);
            }
            value >>= 8;
        }
    }
}

void crypto_bn_from_u64(crypto_bn *r, uint64_t value) {
    crypto_bn_zero(r);
    if (value == 0) {
        return;
    }
    r->v[0] = value;
    r->words = 1;
}

uint64_t crypto_bn_add(crypto_bn *r, const crypto_bn *a, const crypto_bn *b) {
    size_t max_words = (a->words > b->words) ? a->words : b->words;
    uint64_t carry = 0;
    for (size_t i = 0; i < max_words; ++i) {
        uint64_t av = (i < a->words) ? a->v[i] : 0;
        uint64_t bv = (i < b->words) ? b->v[i] : 0;
        unsigned __int128 sum = (unsigned __int128)av + bv + carry;
        r->v[i] = (uint64_t)sum;
        carry = (uint64_t)(sum >> 64);
    }
    if (carry && max_words < CRYPTO_BN_MAX_WORDS) {
        r->v[max_words++] = carry;
        carry = 0;
    }
    r->words = max_words;
    crypto_bn_normalize(r);
    return carry;
}

uint64_t crypto_bn_sub(crypto_bn *r, const crypto_bn *a, const crypto_bn *b) {
    uint64_t borrow = 0;
    size_t max_words = a->words;
    for (size_t i = 0; i < max_words; ++i) {
        uint64_t av = a->v[i];
        uint64_t bv = (i < b->words) ? b->v[i] : 0;
        unsigned __int128 diff = (unsigned __int128)av - bv - borrow;
        r->v[i] = (uint64_t)diff;
        borrow = (uint64_t)((diff >> 127) & 1u);
    }
    r->words = max_words;
    crypto_bn_normalize(r);
    return borrow;
}

int crypto_bn_mul(crypto_bn *r, const crypto_bn *a, const crypto_bn *b) {
    size_t a_words = a->words;
    size_t b_words = b->words;
    if (a_words == 0 || b_words == 0) {
        crypto_bn_zero(r);
        return 1;
    }
    if (a_words + b_words > CRYPTO_BN_MAX_WORDS) {
        return 0;
    }
    for (size_t i = 0; i < CRYPTO_BN_MAX_WORDS; ++i) {
        r->v[i] = 0;
    }
    for (size_t i = 0; i < a_words; ++i) {
        unsigned __int128 carry = 0;
        for (size_t j = 0; j < b_words; ++j) {
            unsigned __int128 cur = (unsigned __int128)a->v[i] * b->v[j];
            cur += r->v[i + j];
            cur += carry;
            r->v[i + j] = (uint64_t)cur;
            carry = cur >> 64;
        }
        r->v[i + b_words] = (uint64_t)carry;
    }
    r->words = a_words + b_words;
    crypto_bn_normalize(r);
    return 1;
}

static void crypto_bn_shift_left(crypto_bn *r, const crypto_bn *a, size_t shift) {
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
    crypto_bn_normalize(r);
}

size_t crypto_bn_bit_length(const crypto_bn *a) {
    if (a->words == 0) {
        return 0;
    }
    uint64_t top = a->v[a->words - 1];
    size_t bits = 0;
    while (top) {
        top >>= 1;
        ++bits;
    }
    return (a->words - 1) * 64 + bits;
}

int crypto_bn_get_bit(const crypto_bn *a, size_t bit) {
    size_t word = bit / 64;
    size_t offset = bit % 64;
    if (word >= a->words) {
        return 0;
    }
    return (int)((a->v[word] >> offset) & 1u);
}

int crypto_bn_mod(crypto_bn *r, const crypto_bn *a, const crypto_bn *mod) {
    if (mod->words == 0) {
        return 0;
    }
    crypto_bn temp;
    crypto_bn_copy(&temp, a);
    if (crypto_bn_cmp(&temp, mod) < 0) {
        crypto_bn_copy(r, &temp);
        return 1;
    }
    size_t mod_bits = crypto_bn_bit_length(mod);
    while (crypto_bn_cmp(&temp, mod) >= 0) {
        size_t temp_bits = crypto_bn_bit_length(&temp);
        if (temp_bits < mod_bits) {
            break;
        }
        size_t shift = temp_bits - mod_bits;
        crypto_bn shifted;
        crypto_bn_shift_left(&shifted, mod, shift);
        if (crypto_bn_cmp(&temp, &shifted) < 0 && shift > 0) {
            crypto_bn_shift_left(&shifted, mod, shift - 1);
        }
        crypto_bn_sub(&temp, &temp, &shifted);
    }
    crypto_bn_copy(r, &temp);
    return 1;
}

int crypto_bn_mod_mul(crypto_bn *r, const crypto_bn *a, const crypto_bn *b, const crypto_bn *mod) {
    crypto_bn tmp;
    if (!crypto_bn_mul(&tmp, a, b)) {
        return 0;
    }
    return crypto_bn_mod(r, &tmp, mod);
}

int crypto_bn_mod_exp(crypto_bn *r, const crypto_bn *a, const crypto_bn *exp, const crypto_bn *mod) {
    if (mod->words == 0) {
        return 0;
    }
    crypto_bn base;
    crypto_bn result;
    crypto_bn_mod(&base, a, mod);
    crypto_bn_from_u64(&result, 1);
    size_t bits = crypto_bn_bit_length(exp);
    for (size_t i = 0; i < bits; ++i) {
        if (crypto_bn_get_bit(exp, i)) {
            if (!crypto_bn_mod_mul(&result, &result, &base, mod)) {
                return 0;
            }
        }
        if (i + 1 < bits) {
            if (!crypto_bn_mod_mul(&base, &base, &base, mod)) {
                return 0;
            }
        }
    }
    crypto_bn_copy(r, &result);
    return 1;
}

int crypto_bn_mod_inv(crypto_bn *r, const crypto_bn *a, const crypto_bn *mod) {
    if (mod->words == 0) {
        return 0;
    }
    if (crypto_bn_is_zero(a)) {
        return 0;
    }
    if (crypto_bn_is_even(mod)) {
        return 0;
    }

    crypto_bn u;
    crypto_bn v;
    crypto_bn x1;
    crypto_bn x2;

    crypto_bn_mod(&u, a, mod);
    crypto_bn_copy(&v, mod);
    crypto_bn_from_u64(&x1, 1);
    crypto_bn_zero(&x2);

    while (crypto_bn_cmp(&u, &v) != 0) {
        while (crypto_bn_is_even(&u)) {
            if (u.words == 0) {
                return 0;
            }
            crypto_bn_rshift1(&u);
            if (crypto_bn_is_even(&x1)) {
                crypto_bn_rshift1(&x1);
            } else {
                crypto_bn tmp;
                crypto_bn_add(&tmp, &x1, mod);
                crypto_bn_copy(&x1, &tmp);
                crypto_bn_rshift1(&x1);
            }
        }
        while (crypto_bn_is_even(&v)) {
            if (v.words == 0) {
                return 0;
            }
            crypto_bn_rshift1(&v);
            if (crypto_bn_is_even(&x2)) {
                crypto_bn_rshift1(&x2);
            } else {
                crypto_bn tmp;
                crypto_bn_add(&tmp, &x2, mod);
                crypto_bn_copy(&x2, &tmp);
                crypto_bn_rshift1(&x2);
            }
        }

        if (crypto_bn_cmp(&u, &v) >= 0) {
            crypto_bn_sub(&u, &u, &v);
            if (crypto_bn_sub(&x1, &x1, &x2)) {
                crypto_bn_add(&x1, &x1, mod);
            }
        } else {
            crypto_bn_sub(&v, &v, &u);
            if (crypto_bn_sub(&x2, &x2, &x1)) {
                crypto_bn_add(&x2, &x2, mod);
            }
        }
    }

    if (u.words == 1 && u.v[0] == 1) {
        crypto_bn_mod(r, &x1, mod);
        return 1;
    }
    if (v.words == 1 && v.v[0] == 1) {
        crypto_bn_mod(r, &x2, mod);
        return 1;
    }
    return 0;
}
