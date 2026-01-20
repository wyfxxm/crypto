#include "sm3.h"

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static uint32_t p0(uint32_t x) {
    return x ^ ROTL32(x, 9) ^ ROTL32(x, 17);
}

static uint32_t p1(uint32_t x) {
    return x ^ ROTL32(x, 15) ^ ROTL32(x, 23);
}

static uint32_t ff(uint32_t x, uint32_t y, uint32_t z, int j) {
    if (j < 16) {
        return x ^ y ^ z;
    }
    return (x & y) | (x & z) | (y & z);
}

static uint32_t gg(uint32_t x, uint32_t y, uint32_t z, int j) {
    if (j < 16) {
        return x ^ y ^ z;
    }
    return (x & y) | ((~x) & z);
}

static void sm3_compress(sm3_ctx *ctx, const uint8_t block[64]) {
    uint32_t w[68];
    uint32_t w1[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = ((uint32_t)block[i * 4] << 24)
            | ((uint32_t)block[i * 4 + 1] << 16)
            | ((uint32_t)block[i * 4 + 2] << 8)
            | (uint32_t)block[i * 4 + 3];
    }
    for (int j = 16; j < 68; ++j) {
        uint32_t tmp = w[j - 16] ^ w[j - 9] ^ ROTL32(w[j - 3], 15);
        w[j] = p1(tmp) ^ ROTL32(w[j - 13], 7) ^ w[j - 6];
    }
    for (int j = 0; j < 64; ++j) {
        w1[j] = w[j] ^ w[j + 4];
    }

    uint32_t a = ctx->state[0];
    uint32_t b = ctx->state[1];
    uint32_t c = ctx->state[2];
    uint32_t d = ctx->state[3];
    uint32_t e = ctx->state[4];
    uint32_t f = ctx->state[5];
    uint32_t g = ctx->state[6];
    uint32_t h = ctx->state[7];

    for (int j = 0; j < 64; ++j) {
        uint32_t t = (j < 16) ? 0x79cc4519 : 0x7a879d8a;
        uint32_t ss1 = ROTL32((ROTL32(a, 12) + e + ROTL32(t, j)) & 0xffffffffu, 7);
        uint32_t ss2 = ss1 ^ ROTL32(a, 12);
        uint32_t tt1 = (ff(a, b, c, j) + d + ss2 + w1[j]) & 0xffffffffu;
        uint32_t tt2 = (gg(e, f, g, j) + h + ss1 + w[j]) & 0xffffffffu;
        d = c;
        c = ROTL32(b, 9);
        b = a;
        a = tt1;
        h = g;
        g = ROTL32(f, 19);
        f = e;
        e = p0(tt2);
    }

    ctx->state[0] ^= a;
    ctx->state[1] ^= b;
    ctx->state[2] ^= c;
    ctx->state[3] ^= d;
    ctx->state[4] ^= e;
    ctx->state[5] ^= f;
    ctx->state[6] ^= g;
    ctx->state[7] ^= h;
}

void sm3_init(sm3_ctx *ctx) {
    ctx->state[0] = 0x7380166f;
    ctx->state[1] = 0x4914b2b9;
    ctx->state[2] = 0x172442d7;
    ctx->state[3] = 0xda8a0600;
    ctx->state[4] = 0xa96f30bc;
    ctx->state[5] = 0x163138aa;
    ctx->state[6] = 0xe38dee4d;
    ctx->state[7] = 0xb0fb0e4e;
    ctx->total_bits = 0;
    ctx->buffer_len = 0;
}

void sm3_update(sm3_ctx *ctx, const uint8_t *data, size_t len) {
    ctx->total_bits += (uint64_t)len * 8;
    while (len > 0) {
        size_t copy_len = 64 - ctx->buffer_len;
        if (copy_len > len) {
            copy_len = len;
        }
        for (size_t i = 0; i < copy_len; ++i) {
            ctx->buffer[ctx->buffer_len + i] = data[i];
        }
        ctx->buffer_len += copy_len;
        data += copy_len;
        len -= copy_len;
        if (ctx->buffer_len == 64) {
            sm3_compress(ctx, ctx->buffer);
            ctx->buffer_len = 0;
        }
    }
}

void sm3_final(sm3_ctx *ctx, uint8_t out[32]) {
    size_t i = ctx->buffer_len;
    ctx->buffer[i++] = 0x80;
    if (i > 56) {
        while (i < 64) {
            ctx->buffer[i++] = 0;
        }
        sm3_compress(ctx, ctx->buffer);
        i = 0;
    }
    while (i < 56) {
        ctx->buffer[i++] = 0;
    }
    uint64_t bits = ctx->total_bits;
    for (int j = 7; j >= 0; --j) {
        ctx->buffer[i++] = (uint8_t)(bits >> (j * 8));
    }
    sm3_compress(ctx, ctx->buffer);

    for (int j = 0; j < 8; ++j) {
        out[j * 4] = (uint8_t)(ctx->state[j] >> 24);
        out[j * 4 + 1] = (uint8_t)(ctx->state[j] >> 16);
        out[j * 4 + 2] = (uint8_t)(ctx->state[j] >> 8);
        out[j * 4 + 3] = (uint8_t)(ctx->state[j]);
    }
}

void sm3_hash(const uint8_t *data, size_t len, uint8_t out[32]) {
    sm3_ctx ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, data, len);
    sm3_final(&ctx, out);
}
