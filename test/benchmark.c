#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "time.h"

#ifdef _WIN32
#include <windows.h>
#endif

#include "util.h"

static volatile uint32_t benchmark_sink;

static double benchmark_now(void) {
#ifdef _WIN32
    static LARGE_INTEGER frequency;
    LARGE_INTEGER counter;
    if(frequency.QuadPart == 0 && !QueryPerformanceFrequency(&frequency)) {
        fprintf(stderr, "performance timer unavailable\n");
        exit(1);
    }
    if(!QueryPerformanceCounter(&counter)) {
        fprintf(stderr, "performance timer failed\n");
        exit(1);
    }
    return (double)counter.QuadPart / (double)frequency.QuadPart;
#elif defined(CLOCK_MONOTONIC)
    struct timespec now;
    if(clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        perror("clock_gettime");
        exit(1);
    }
    return (double)now.tv_sec + (double)now.tv_nsec / 1000000000.0;
#else
    return (double)clock() / (double)CLOCKS_PER_SEC;
#endif
}

static size_t benchmark_iterations(size_t plaintext_len) {
    const size_t TARGET_BYTES = 64U * 1024U * 1024U;
    size_t iterations;

    if(plaintext_len == 0) {
        return 200000;
    }

    iterations = TARGET_BYTES / plaintext_len;
    if(iterations < 64) {
        iterations = 64;
    } else if(iterations > 200000) {
        iterations = 200000;
    }

    return iterations;
}

static int benchmark_size(
    const cbsiv_ctx_t* const ctx,
    size_t plaintext_len
) {
    enum { AD_LEN = 32 };

    const size_t ALLOCATION_SIZE = plaintext_len == 0 ? 1 : plaintext_len;
    const size_t ITERATIONS = benchmark_iterations(plaintext_len);
    uint8_t* const plaintext = malloc(ALLOCATION_SIZE);
    uint8_t* const ciphertext = malloc(ALLOCATION_SIZE);
    uint8_t* const changed_ciphertext = malloc(ALLOCATION_SIZE);
    uint8_t* const decrypted = malloc(ALLOCATION_SIZE);
    cbsiv_chacha20_nonce_t nonce;
    uint8_t ad[AD_LEN];
    cbsiv_iv_t iv;
    cbsiv_iv_t changed_iv;
    cbsiv_res_t result = CBSIV_OK;
    double start;
    double elapsed;
    int ret = 0;

    if(
        plaintext == NULL ||
        ciphertext == NULL ||
        changed_ciphertext == NULL ||
        decrypted == NULL
    ) {
        fprintf(
            stderr, "allocation failed for %zu-byte benchmark\n",
            plaintext_len
        );
        ret = 1;
        goto cleanup;
    }

    fill_bytes(plaintext, plaintext_len, 0x31U);
    memset(ciphertext, 0, ALLOCATION_SIZE);
    memset(changed_ciphertext, 0, ALLOCATION_SIZE);
    memset(decrypted, 0, ALLOCATION_SIZE);
    fill_bytes(nonce, sizeof(nonce), 0x53U);
    fill_bytes(ad, sizeof(ad), 0x75U);

    result = cbsiv_encrypt(
        ctx,
        plaintext_len, plaintext,
        sizeof(ad), ad,
        nonce,
        ciphertext, iv
    );
    if(result != CBSIV_OK) {
        fprintf(
            stderr, "setup encryption failed for %zu bytes\n",
            plaintext_len
        );
        ret = 1;
        goto cleanup;
    }

    result = cbsiv_decrypt(
        ctx,
        plaintext_len, ciphertext,
        sizeof(ad), ad,
        nonce, iv,
        decrypted
    );
    if(result != CBSIV_OK || memcmp(plaintext, decrypted, plaintext_len) != 0) {
        fprintf(stderr, "setup verification failed for %zu bytes\n", plaintext_len);
        ret = 1;
        goto cleanup;
    }

    start = benchmark_now();
    for(size_t i = 0; i < ITERATIONS; i++) {
        result = cbsiv_encrypt(
            ctx,
            plaintext_len, plaintext,
            sizeof(ad), ad,
            nonce,
            ciphertext, iv
        );
        benchmark_sink += (uint32_t)result + ciphertext[0] + iv[0];
    }
    elapsed = benchmark_now() - start;
    print_timing("encrypt", plaintext_len, ITERATIONS, elapsed);
    if(result != CBSIV_OK) {
        fprintf(stderr, "encryption failed for %zu bytes\n", plaintext_len);
        ret = 1;
        goto cleanup;
    }

    start = benchmark_now();
    for(size_t i = 0; i < ITERATIONS; i++) {
        result = cbsiv_decrypt(
            ctx,
            plaintext_len, ciphertext,
            sizeof(ad), ad,
            nonce, iv,
            decrypted
        );
        benchmark_sink += (uint32_t)result + decrypted[0];
    }
    elapsed = benchmark_now() - start;
    print_timing(
        "decrypt/verify success",
        plaintext_len, ITERATIONS, elapsed
    );
    if(result != CBSIV_OK || memcmp(plaintext, decrypted, plaintext_len) != 0) {
        fprintf(stderr, "verification failed for %zu bytes\n", plaintext_len);
        ret = 1;
        goto cleanup;
    }

    memcpy(changed_iv, iv, sizeof(iv));
    changed_iv[0] ^= 1U;
    start = benchmark_now();
    for(size_t i = 0; i < ITERATIONS; i++) {
        result = cbsiv_decrypt(
            ctx,
            plaintext_len, ciphertext,
            sizeof(ad), ad,
            nonce, changed_iv,
            decrypted
        );
        benchmark_sink += (uint32_t)result + decrypted[0];
    }
    elapsed = benchmark_now() - start;
    print_timing("decrypt/bad tag", plaintext_len, ITERATIONS, elapsed);
    if(result != CBSIV_VERIFICATION_FAILED) {
        fprintf(
            stderr, "bad tag unexpectedly verified for %zu bytes\n",
            plaintext_len
        );
        ret = 1;
        goto cleanup;
    }

    if(plaintext_len != 0) {
        memcpy(changed_ciphertext, ciphertext, plaintext_len);
        changed_ciphertext[plaintext_len / 2] ^= 0x80U;

        start = benchmark_now();
        for(size_t i = 0; i < ITERATIONS; i++) {
            result = cbsiv_decrypt(
                ctx,
                plaintext_len, changed_ciphertext,
                sizeof(ad), ad,
                nonce, iv,
                decrypted
            );
            benchmark_sink += (uint32_t)result + decrypted[0];
        }
        elapsed = benchmark_now() - start;
        print_timing(
            "decrypt/bad ciphertext",
            plaintext_len, ITERATIONS, elapsed
        );
        if(result != CBSIV_VERIFICATION_FAILED) {
            fprintf(
                stderr,
                "bad ciphertext unexpectedly verified for %zu bytes\n",
                plaintext_len
            );
            ret = 1;
            goto cleanup;
        }
    }

cleanup:
    free(plaintext);
    free(ciphertext);
    free(changed_ciphertext);
    free(decrypted);
    return ret;
}

static void benchmark_initialization(void) {
    enum { ITERATIONS = 200000 };

    cbsiv_ctx_t ctx;
    cbsiv_master_key_t key;
    double start;
    double elapsed;

    fill_bytes(key, sizeof(key), 0x17U);
    start = benchmark_now();
    for(size_t i = 0; i < ITERATIONS; i++) {
        cbsiv_init(key, &ctx);
        benchmark_sink += ctx.enc_key[0] + ctx.mac_key[0];
    }
    elapsed = benchmark_now() - start;
    print_timing("initialize", 0, ITERATIONS, elapsed);
}

int main(void) {
    static const size_t SIZES[] = {
        0,
        16,
        64,
        256,
        1024,
        4096,
        16384,
        65536,
        262144,
        1048576
    };

    cbsiv_ctx_t ctx;

    make_context(&ctx, 0x29U);

    printf(
        "cbsiv-%u benchmark\n",
        CBSIV_IVLEN * 8U
    );
    printf("ChaChaSlide backend; key-committing IV; associated data=32 B\n");
#ifdef _WIN32
    printf("timer: QueryPerformanceCounter\n");
#elif defined(CLOCK_MONOTONIC)
    printf("timer: CLOCK_MONOTONIC\n");
#else
    printf("timer: clock (1/%ld second)\n", (long)CLOCKS_PER_SEC);
#endif
    printf("single thread, hot cache; includes setup and finalization\n\n");
    printf("%-24s %10s  %16s  %16s\n", "OPERATION", "PLAINTEXT", "TIME", "THROUGHPUT");
    benchmark_initialization();

    for(size_t i = 0; i < sizeof(SIZES) / sizeof(SIZES[0]); i++) {
        if(benchmark_size(&ctx, SIZES[i]) != 0) {
            return 1;
        }
    }

    printf("benchmark sink: %u\n", (unsigned)benchmark_sink);
    return 0;
}
