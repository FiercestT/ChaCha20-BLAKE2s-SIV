#include "cbsiv.h"
#include "ccs_blake2.h"
#include "ccs_chacha.h"

// Utilities from ChaChaSlide, Copyright (c) 2026 FiercestT, MIT (lib/ChaChaSlide/LICENSE).
/**
 * @brief Overwrite a memory region with zeroes.
 *
 * @param in_len Byte length of the memory region.
 * @param in The memory region to overwrite.
 */
static inline void cbsiv_util_memzero(size_t in_len, void* in) {
    for(size_t i = 0; i < in_len; i++) {
        ((volatile uint8_t*)in)[i] = 0;
    }
}

/**
 * @brief Store a 32-bit integer in little-endian order.
 *
 * @param value The integer to encode.
 * @param out [4] The output buffer.
 */
static inline void cbsiv_util_store32le(uint32_t value, uint8_t* out) {
    out[0] = (uint8_t)(value);
    out[1] = (uint8_t)(value >> 8);
    out[2] = (uint8_t)(value >> 16);
    out[3] = (uint8_t)(value >> 24);
}

/**
 * @brief Store a 64-bit integer in little-endian order.
 *
 * @param value The integer to encode.
 * @param out [8] The output buffer.
 */
static inline void cbsiv_util_store64le(uint64_t value, uint8_t* out) {
    cbsiv_util_store32le((uint32_t)value, out);
    cbsiv_util_store32le((uint32_t)(value >> 32), &out[4]);
}

/**
 * @brief Compare two authentication IVs in constant time.
 *
 * @param iv1 [CBSIV_IVLEN] The first IV.
 * @param iv2 [CBSIV_IVLEN] The second IV.
 * @return 1 if the IVs match or 0 otherwise.
 */
static inline uint8_t cbsiv_iv_cmp(const cbsiv_iv_t iv1, const cbsiv_iv_t iv2) {
    uint8_t ret = 0; 
    for(int i = 0; i < CBSIV_IVLEN; i++)
        ret |= iv1[i] ^ iv2[i];

    return !ret;
}

static inline void cbsiv_derive_subkey(
    const cbsiv_ctx_t* ctx,
    const cbsiv_iv_t iv,
    const cbsiv_chacha20_nonce_t nonce,
    cbsiv_chacha20_key_t subkey
) {
    ccs_blake2s_ctx_t state;
    ccs_blake2s_init(&state, CBSIV_CHACHA20_KEYLEN);
    ccs_blake2s_config_key(&state, ctx->enc_key);
    ccs_blake2s_update(&state, CBSIV_CHACHA20_NONCELEN, nonce);
    ccs_blake2s_update(&state, CBSIV_IVLEN, iv);
    ccs_blake2s_update(&state, 7, (const uint8_t*)"kdf/sub");
    ccs_blake2s_final(&state, subkey);
}

static inline void cbsiv_iv(
    const cbsiv_ctx_t* ctx,
    size_t plaintext_len,
    const uint8_t* plaintext,
    size_t ad_len,
    const uint8_t* ad,
    const cbsiv_chacha20_nonce_t nonce,
    cbsiv_iv_t iv
) {
    uint8_t lengths[16];
    cbsiv_util_store64le((uint64_t)plaintext_len, lengths);
    cbsiv_util_store64le((uint64_t)ad_len, lengths + 8);

    ccs_blake2s_ctx_t state;
    ccs_blake2s_digest_t digest;
    ccs_blake2s_init(&state, CBSIV_IVLEN);
    ccs_blake2s_config_key(&state, ctx->mac_key);
    ccs_blake2s_update(&state, CBSIV_CHACHA20_KEYLEN, ctx->enc_key);
    ccs_blake2s_update(&state, sizeof(lengths), lengths);
    ccs_blake2s_update(&state, plaintext_len, plaintext);
    ccs_blake2s_update(&state, ad_len, ad);
    ccs_blake2s_update(&state, CBSIV_CHACHA20_NONCELEN, nonce);
    ccs_blake2s_final(&state, digest);
    for(size_t i = 0; i < CBSIV_IVLEN; i++)
        iv[i] = digest[i];
}

void cbsiv_init(
    cbsiv_ctx_t* ctx,
    const cbsiv_master_key_t master_key
) {
    const uint8_t ENC_CTX[] = "kdf/enc";
    const uint8_t MAC_CTX[] = "kdf/mac";

    ccs_blake2s_ctx_t state;
    ccs_blake2s_init(&state, CBSIV_CHACHA20_KEYLEN);
    ccs_blake2s_config_key(&state, master_key);
    ccs_blake2s_update(&state, sizeof(ENC_CTX) - 1, ENC_CTX);
    ccs_blake2s_final(&state, ctx->enc_key);

    ccs_blake2s_init(&state, CBSIV_BLAKE2S_KEYLEN);
    ccs_blake2s_config_key(&state, master_key);
    ccs_blake2s_update(&state, sizeof(MAC_CTX) - 1, MAC_CTX);
    ccs_blake2s_final(&state, ctx->mac_key);
}

void cbsiv_increment_nonce(
    cbsiv_chacha20_nonce_t nonce,
    uint32_t n
) {
    uint16_t carry = 0;

    for(size_t i = 0; i < CBSIV_CHACHA20_NONCELEN; i++) {
        const uint16_t sum = nonce[i] + (uint8_t)n + carry;

        nonce[i] = (uint8_t)sum;
        carry = sum >> 8;
        n >>= 8;
    }
}

cbsiv_res_t cbsiv_encrypt(
    const cbsiv_ctx_t* ctx,
    const cbsiv_chacha20_nonce_t nonce,
    size_t plaintext_len,
    const uint8_t* plaintext,
    size_t ad_len,
    const uint8_t* ad,
    uint8_t* ciphertext,
    cbsiv_iv_t iv
) {
    if(plaintext_len != 0 && (plaintext_len - 1) / CCS_CHACHA_BLOCKLEN > UINT32_MAX)
        return CBSIV_INVALID_LENGTH;

    // IV
    cbsiv_iv(ctx, plaintext_len, plaintext, ad_len, ad, nonce, iv);

    // Subkey
    cbsiv_chacha20_key_t subkey_buffer;
    cbsiv_derive_subkey(ctx, iv, nonce, subkey_buffer);

    // Encrypt
    ccs_chacha20_ietf(subkey_buffer, nonce, plaintext_len, plaintext, ciphertext);
    cbsiv_util_memzero(sizeof(subkey_buffer), subkey_buffer);

    return CBSIV_OK;
}

cbsiv_res_t cbsiv_decrypt(
    const cbsiv_ctx_t* ctx,
    const cbsiv_chacha20_nonce_t nonce,
    const cbsiv_iv_t iv,
    size_t ciphertext_len,
    const uint8_t* ciphertext,
    size_t ad_len,
    const uint8_t* ad,
    uint8_t* plaintext
) {
    if(ciphertext_len != 0 && (ciphertext_len - 1) / CCS_CHACHA_BLOCKLEN > UINT32_MAX)
        return CBSIV_INVALID_LENGTH;

    // Subkey
    cbsiv_chacha20_key_t subkey_buffer;
    cbsiv_derive_subkey(ctx, iv, nonce, subkey_buffer);

    // Decrypt
    ccs_chacha20_ietf(subkey_buffer, nonce, ciphertext_len, ciphertext, plaintext);
    cbsiv_util_memzero(sizeof(subkey_buffer), subkey_buffer);

    // IV
    cbsiv_iv_t iv_computed;
    cbsiv_iv(ctx, ciphertext_len, plaintext, ad_len, ad, nonce, iv_computed);

    if(!cbsiv_iv_cmp(iv, iv_computed)) {
        cbsiv_util_memzero(ciphertext_len, plaintext);
        return CBSIV_VERIFICATION_FAILED;
    }

    return CBSIV_OK;
}
