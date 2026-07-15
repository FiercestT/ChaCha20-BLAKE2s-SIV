#include "stdio.h"
#include "string.h"

#include "util.h"

#define TEST_BUFFER_SIZE 257

static int test_failures;

static void check(
    int condition,
    const char* const expression,
    const char* const file,
    int line
) {
    if(condition) {
        return;
    }

    fprintf(stderr, "FAIL %s:%d: %s\n", file, line, expression);
    test_failures++;
}

#define CHECK(condition) check((condition), #condition, __FILE__, __LINE__)

static void test_round_trip(
    size_t plaintext_len,
    size_t ad_len
) {
    cc20_b2s_ctx_t ctx;
    cc20_b2s_siv_chacha20_nonce_t nonce;
    uint8_t plaintext[TEST_BUFFER_SIZE];
    uint8_t ciphertext[TEST_BUFFER_SIZE];
    uint8_t ciphertext_again[TEST_BUFFER_SIZE];
    uint8_t decrypted[TEST_BUFFER_SIZE];
    uint8_t ad[TEST_BUFFER_SIZE];
    cc20_b2s_siv_iv_t iv;
    cc20_b2s_siv_iv_t iv_again;

    CHECK(plaintext_len <= sizeof(plaintext));
    CHECK(ad_len <= sizeof(ad));
    if(plaintext_len > sizeof(plaintext) || ad_len > sizeof(ad)) {
        return;
    }

    make_context(&ctx, 0x21U);
    fill_bytes(nonce, sizeof(nonce), 0x42U);
    fill_bytes(plaintext, sizeof(plaintext), 0x63U);
    fill_bytes(ad, sizeof(ad), 0x84U);

    CHECK(cc20_b2s_siv_encrypt(
        &ctx,
        plaintext_len, plaintext,
        ad_len, ad,
        nonce,
        ciphertext, iv
    ) == SIV_OK);

    CHECK(cc20_b2s_siv_decrypt(
        &ctx,
        plaintext_len, ciphertext,
        ad_len, ad,
        nonce, iv,
        decrypted
    ) == SIV_OK);
    CHECK(memcmp(plaintext, decrypted, plaintext_len) == 0);

    CHECK(cc20_b2s_siv_encrypt(
        &ctx,
        plaintext_len, plaintext,
        ad_len, ad,
        nonce,
        ciphertext_again, iv_again
    ) == SIV_OK);
    CHECK(memcmp(ciphertext, ciphertext_again, plaintext_len) == 0);
    CHECK(memcmp(iv, iv_again, sizeof(iv)) == 0);
}

static void test_round_trips(void) {
    static const struct {
        size_t plaintext_len;
        size_t ad_len;
    } cases[] = {
        { 0, 0 },
        { 0, 17 },
        { 1, 0 },
        { 15, 1 },
        { 16, 16 },
        { 63, 17 },
        { 64, 64 },
        { 65, 63 },
        { 255, 65 },
        { 256, 256 },
        { 257, 257 }
    };

    for(size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        test_round_trip(cases[i].plaintext_len, cases[i].ad_len);
    }
}

static void expect_verification_failure(
    const cc20_b2s_ctx_t* const ctx,
    size_t ciphertext_len,
    const uint8_t ciphertext[const ciphertext_len],
    size_t ad_len,
    const uint8_t ad[const ad_len],
    const cc20_b2s_siv_chacha20_nonce_t nonce,
    const cc20_b2s_siv_iv_t iv
) {
    uint8_t decrypted[TEST_BUFFER_SIZE];

    CHECK(ciphertext_len <= sizeof(decrypted));
    if(ciphertext_len > sizeof(decrypted)) {
        return;
    }

    memset(decrypted, 0xA5, sizeof(decrypted));
    CHECK(cc20_b2s_siv_decrypt(
        ctx,
        ciphertext_len, ciphertext,
        ad_len, ad,
        nonce, iv,
        decrypted
    ) == SIV_VERIFICATION_FAILED);
    CHECK(all_zero(decrypted, ciphertext_len));
}

static void test_verification_failures(void) {
    enum {
        PLAINTEXT_LEN = 96,
        AD_LEN = 33
    };

    cc20_b2s_ctx_t ctx;
    cc20_b2s_ctx_t wrong_ctx;
    cc20_b2s_siv_chacha20_nonce_t nonce;
    cc20_b2s_siv_chacha20_nonce_t changed_nonce;
    uint8_t plaintext[PLAINTEXT_LEN];
    uint8_t ciphertext[PLAINTEXT_LEN];
    uint8_t changed_ciphertext[PLAINTEXT_LEN];
    uint8_t ad[AD_LEN];
    uint8_t changed_ad[AD_LEN];
    cc20_b2s_siv_iv_t iv;
    cc20_b2s_siv_iv_t changed_iv;

    make_context(&ctx, 0x11U);
    make_context(&wrong_ctx, 0x12U);
    fill_bytes(nonce, sizeof(nonce), 0x23U);
    fill_bytes(plaintext, sizeof(plaintext), 0x45U);
    fill_bytes(ad, sizeof(ad), 0x67U);

    CHECK(cc20_b2s_siv_encrypt(
        &ctx,
        sizeof(plaintext), plaintext,
        sizeof(ad), ad,
        nonce,
        ciphertext, iv
    ) == SIV_OK);

    memcpy(changed_iv, iv, sizeof(iv));
    changed_iv[0] ^= 0x01U;
    expect_verification_failure(
        &ctx, sizeof(ciphertext), ciphertext,
        sizeof(ad), ad, nonce, changed_iv
    );

    memcpy(changed_ciphertext, ciphertext, sizeof(ciphertext));
    changed_ciphertext[sizeof(changed_ciphertext) / 2] ^= 0x80U;
    expect_verification_failure(
        &ctx, sizeof(changed_ciphertext), changed_ciphertext,
        sizeof(ad), ad, nonce, iv
    );

    memcpy(changed_ad, ad, sizeof(ad));
    changed_ad[sizeof(changed_ad) - 1] ^= 0x40U;
    expect_verification_failure(
        &ctx, sizeof(ciphertext), ciphertext,
        sizeof(changed_ad), changed_ad, nonce, iv
    );

    memcpy(changed_nonce, nonce, sizeof(nonce));
    changed_nonce[sizeof(changed_nonce) - 1] ^= 0x20U;
    expect_verification_failure(
        &ctx, sizeof(ciphertext), ciphertext,
        sizeof(ad), ad, changed_nonce, iv
    );

    expect_verification_failure(
        &wrong_ctx, sizeof(ciphertext), ciphertext,
        sizeof(ad), ad, nonce, iv
    );
}

static void test_empty_inputs(void) {
    cc20_b2s_ctx_t ctx;
    uint8_t placeholder = 0;
    cc20_b2s_siv_chacha20_nonce_t nonce;
    uint8_t ad[17];
    uint8_t changed_ad[17];
    cc20_b2s_siv_iv_t iv;

    make_context(&ctx, 0x91U);
    fill_bytes(nonce, sizeof(nonce), 0x37U);
    fill_bytes(ad, sizeof(ad), 0x73U);

    CHECK(cc20_b2s_siv_encrypt(
        &ctx,
        0, &placeholder,
        sizeof(ad), ad,
        nonce,
        &placeholder, iv
    ) == SIV_OK);
    CHECK(cc20_b2s_siv_decrypt(
        &ctx,
        0, &placeholder,
        sizeof(ad), ad,
        nonce, iv,
        &placeholder
    ) == SIV_OK);

    memcpy(changed_ad, ad, sizeof(ad));
    changed_ad[0] ^= 1U;
    expect_verification_failure(
        &ctx, 0, &placeholder,
        sizeof(changed_ad), changed_ad, nonce, iv
    );
}

static void test_increment_nonce(void) {
    cc20_b2s_siv_chacha20_nonce_t nonce = {
        0xFEU, 0xFFU, 0x00U
    };
    const cc20_b2s_siv_chacha20_nonce_t expected = {
        0x00U, 0x01U, 0x01U
    };

    cc20_b2s_siv_increment_nonce(nonce, UINT32_C(0x0102));
    CHECK(memcmp(nonce, expected, sizeof(nonce)) == 0);

    memset(nonce, 0xFF, sizeof(nonce));
    cc20_b2s_siv_increment_nonce(nonce, 1);
    CHECK(all_zero(nonce, sizeof(nonce)));
}

static void test_length_limit(void) {
#if SIZE_MAX > UINT32_MAX
    cc20_b2s_ctx_t ctx;
    uint8_t placeholder = 0;
    cc20_b2s_siv_chacha20_nonce_t nonce = { 0 };
    cc20_b2s_siv_iv_t iv = { 0 };
    volatile size_t invalid_len = ((size_t)1U << 38) + 1U;

    make_context(&ctx, 0x19U);

    CHECK(cc20_b2s_siv_encrypt(
        &ctx,
        invalid_len, &placeholder,
        0, &placeholder,
        nonce,
        &placeholder, iv
    ) == SIV_INVALID_LENGTH);
    CHECK(cc20_b2s_siv_decrypt(
        &ctx,
        invalid_len, &placeholder,
        0, &placeholder,
        nonce, iv,
        &placeholder
    ) == SIV_INVALID_LENGTH);
#endif
}

int main(void) {
    test_round_trips();
    test_empty_inputs();
    test_increment_nonce();
    test_verification_failures();
    test_length_limit();

    if(test_failures != 0) {
        fprintf(
            stderr, "cc20-b2s-siv-%u functional tests: %d failure(s)\n",
            CC20_B2S_SIV_IVLEN * 8, test_failures
        );
        return 1;
    }

    printf(
        "cc20-b2s-siv-%u functional tests: passed\n",
        CC20_B2S_SIV_IVLEN * 8U
    );
    return 0;
}
