#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "time.h"

#include "util.h"

static volatile uint32_t benchmark_sink;

static size_t benchmark_iterations(size_t plaintext_len) {
    const size_t TARGET_BYTES = 16U * 1024U * 1024U;
    size_t iterations;

    if(plaintext_len == 0) {
        return 50000;
    }

    iterations = TARGET_BYTES / plaintext_len;
    if(iterations < 20) {
        iterations = 20;
    } else if(iterations > 100000) {
        iterations = 100000;
    }

    return iterations;
}

static int benchmark_size(
    const cc20_b2s_ctx_t* const ctx,
    size_t plaintext_len
) {
    enum { AD_LEN = 32 };

    const size_t ALLOCATION_SIZE = plaintext_len == 0 ? 1 : plaintext_len;
    const size_t ITERATIONS = benchmark_iterations(plaintext_len);
    uint8_t* const plaintext = malloc(ALLOCATION_SIZE);
    uint8_t* const ciphertext = malloc(ALLOCATION_SIZE);
    uint8_t* const changed_ciphertext = malloc(ALLOCATION_SIZE);
    uint8_t* const decrypted = malloc(ALLOCATION_SIZE);
    cc20_b2s_siv_chacha20_nonce_t nonce;
    uint8_t ad[AD_LEN];
    cc20_b2s_siv_iv_t iv;
    cc20_b2s_siv_iv_t changed_iv;
    cc20_b2s_siv_res_t result = SIV_OK;
    clock_t start;
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

    result = cc20_b2s_siv_encrypt(
        ctx,
        plaintext_len, plaintext,
        sizeof(ad), ad,
        nonce,
        ciphertext, iv
    );
    if(result != SIV_OK) {
        fprintf(
            stderr, "setup encryption failed for %zu bytes\n",
            plaintext_len
        );
        ret = 1;
        goto cleanup;
    }

    start = clock();
    for(size_t i = 0; i < ITERATIONS; i++) {
        result = cc20_b2s_siv_encrypt(
            ctx,
            plaintext_len, plaintext,
            sizeof(ad), ad,
            nonce,
            ciphertext, iv
        );
    }
    elapsed = seconds_since(start);
    print_timing("encrypt", plaintext_len, ITERATIONS, elapsed);
    benchmark_sink += (uint32_t)result + ciphertext[0] + iv[0];

    start = clock();
    for(size_t i = 0; i < ITERATIONS; i++) {
        result = cc20_b2s_siv_decrypt(
            ctx,
            plaintext_len, ciphertext,
            sizeof(ad), ad,
            nonce, iv,
            decrypted
        );
    }
    elapsed = seconds_since(start);
    print_timing(
        "decrypt/verify success",
        plaintext_len, ITERATIONS, elapsed
    );
    benchmark_sink += (uint32_t)result + decrypted[0];

    memcpy(changed_iv, iv, sizeof(iv));
    changed_iv[0] ^= 1U;
    start = clock();
    for(size_t i = 0; i < ITERATIONS; i++) {
        result = cc20_b2s_siv_decrypt(
            ctx,
            plaintext_len, ciphertext,
            sizeof(ad), ad,
            nonce, changed_iv,
            decrypted
        );
    }
    elapsed = seconds_since(start);
    print_timing("decrypt/bad tag", plaintext_len, ITERATIONS, elapsed);
    if(result != SIV_VERIFICATION_FAILED) {
        fprintf(
            stderr, "bad tag unexpectedly verified for %zu bytes\n",
            plaintext_len
        );
        ret = 1;
        goto cleanup;
    }
    benchmark_sink += (uint32_t)result + decrypted[0];

    if(plaintext_len != 0) {
        memcpy(changed_ciphertext, ciphertext, plaintext_len);
        changed_ciphertext[plaintext_len / 2] ^= 0x80U;

        start = clock();
        for(size_t i = 0; i < ITERATIONS; i++) {
            result = cc20_b2s_siv_decrypt(
                ctx,
                plaintext_len, changed_ciphertext,
                sizeof(ad), ad,
                nonce, iv,
                decrypted
            );
        }
        elapsed = seconds_since(start);
        print_timing(
            "decrypt/bad ciphertext",
            plaintext_len, ITERATIONS, elapsed
        );
        if(result != SIV_VERIFICATION_FAILED) {
            fprintf(
                stderr,
                "bad ciphertext unexpectedly verified for %zu bytes\n",
                plaintext_len
            );
            ret = 1;
            goto cleanup;
        }
        benchmark_sink += (uint32_t)result + decrypted[0];
    }

cleanup:
    free(plaintext);
    free(ciphertext);
    free(changed_ciphertext);
    free(decrypted);
    return ret;
}

static void benchmark_initialization(void) {
    enum { ITERATIONS = 100000 };

    cc20_b2s_ctx_t ctx;
    cc20_b2s_siv_master_key_t key;
    clock_t start;
    double elapsed;

    fill_bytes(key, sizeof(key), 0x17U);
    start = clock();
    for(size_t i = 0; i < ITERATIONS; i++) {
        cc20_b2s_siv_init(key, &ctx);
    }
    elapsed = seconds_since(start);
    print_timing("initialize", 0, ITERATIONS, elapsed);
    benchmark_sink += ctx.enc_key[0] + ctx.mac_key[0];
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

    cc20_b2s_ctx_t ctx;

    make_context(&ctx, 0x29U);

    printf(
        "cc20-b2s-siv-%u benchmark\n",
        CC20_B2S_SIV_IVLEN * 8U
    );
    printf("clock resolution: 1/%ld second\n\n", (long)CLOCKS_PER_SEC);
    benchmark_initialization();

    for(size_t i = 0; i < sizeof(SIZES) / sizeof(SIZES[0]); i++) {
        if(benchmark_size(&ctx, SIZES[i]) != 0) {
            return 1;
        }
    }

    printf("benchmark sink: %u\n", (unsigned)benchmark_sink);
    return 0;
}
