#ifndef SM3_H
#define SM3_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t state[8];
    uint64_t total_bits;
    uint8_t buffer[64];
    size_t buffer_len;
} sm3_ctx;

void sm3_init(sm3_ctx *ctx);
void sm3_update(sm3_ctx *ctx, const uint8_t *data, size_t len);
void sm3_final(sm3_ctx *ctx, uint8_t out[32]);
void sm3_hash(const uint8_t *data, size_t len, uint8_t out[32]);

#ifdef __cplusplus
}
#endif

#endif
