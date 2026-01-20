#include "sm3.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
    for (size_t i = 0; i < out_len; ++i) {
        unsigned int byte = 0;
        sscanf(hex + (i * 2), "%2x", &byte);
        out[i] = (uint8_t)byte;
    }
}

static void test_sm3_vector(const char *msg, const char *expected_hex) {
    uint8_t digest[32];
    uint8_t expected[32];

    sm3_hash((const uint8_t *)msg, strlen(msg), digest);
    hex_to_bytes(expected_hex, expected, sizeof(expected));
    assert(memcmp(digest, expected, sizeof(digest)) == 0);
}

int main(void) {
    test_sm3_vector("abc", "66c7f0f462eeedd9d1f2d46bdc10e4e2"
                           "4167c4875cf2f7a2297da02b8f4ba8e0");
    test_sm3_vector("abcdabcdabcdabcdabcdabcdabcdabcd"
                    "abcdabcdabcdabcdabcdabcdabcdabcd",
                    "debe9ff92275b8a138604889c18e5a4d"
                    "6fdb70e5387e5765293dcba39c0c5732");
    puts("SM3 tests passed.");
    return 0;
}
