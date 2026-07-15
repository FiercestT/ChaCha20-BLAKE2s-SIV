#ifndef CC20_B2S_SIV_TEST_UTIL_H
#define CC20_B2S_SIV_TEST_UTIL_H

#include "stddef.h"
#include "stdint.h"
#include "stdio.h"
#include "time.h"

#include "cc20_b2s_siv.h"

static inline void fill_bytes(
    uint8_t* const buffer,
    size_t length,
    uint8_t seed
) {
    for(size_t i = 0; i < length; i++) {
        buffer[i] = (uint8_t)(seed + (uint8_t)(i * 29U));
    }
}

static inline uint8_t all_zero(
    const uint8_t* const buffer,
    size_t length
) {
    uint8_t value = 0;

    for(size_t i = 0; i < length; i++) {
        value |= buffer[i];
    }

    return value == 0;
}

static inline void make_context(
    cc20_b2s_ctx_t* const ctx,
    uint8_t seed
) {
    uint8_t key[MASTER_KEYLEN];

    fill_bytes(key, sizeof(key), seed);
    cc20_b2s_siv_init(key, ctx);
}

static inline double seconds_since(clock_t start) {
    return (double)(clock() - start) / (double)CLOCKS_PER_SEC;
}

static inline void print_timing(
    const char* const operation,
    size_t plaintext_len,
    size_t iterations,
    double seconds
) {
    const double microseconds = seconds * 1000000.0 / (double)iterations;

    if(plaintext_len == 0 || seconds == 0.0) {
        printf(
            "%-24s %8zu B  %10.3f us/op\n",
            operation, plaintext_len, microseconds
        );
        return;
    }

    const double mib = (
        (double)plaintext_len * (double)iterations
    ) / (1024.0 * 1024.0);

    printf(
        "%-24s %8zu B  %10.3f us/op  %10.2f MiB/s\n",
        operation, plaintext_len, microseconds, mib / seconds
    );
}

#endif // CC20_B2S_SIV_TEST_UTIL_H
