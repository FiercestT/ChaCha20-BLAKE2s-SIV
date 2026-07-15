#include "cc20_b2s_siv.h"
#include "string.h"
#include "blake2s.h"
#include "chacha20.h"

static inline void store32_le(uint8_t out[const 4], uint32_t value) {
    out[0] = (uint8_t)(value);
    out[1] = (uint8_t)(value >> 8);
    out[2] = (uint8_t)(value >> 16);
    out[3] = (uint8_t)(value >> 24);
}

static inline void store64_le(uint8_t out[const 8], uint64_t value) {
    store32_le(out,     (uint32_t)value);
    store32_le(out + 4, (uint32_t)(value >> 32));
}

/**
 * Constant time compare of two IVs.
 * 1 = match, 0 = no match
 */
static inline uint8_t iv_cmp(
    const uint8_t iv1[const CC20_B2S_SIV_IVLEN],
    const uint8_t iv2[const CC20_B2S_SIV_IVLEN]
) {
    uint8_t ret = 0; 
    for(int i = 0; i < CC20_B2S_SIV_IVLEN; i++) 
        ret |= iv1[i] ^ iv2[i];

    return !ret;
}

static inline void cc20_b2s_siv_derive_subkey(
    const cc20_b2s_ctx_t* const ctx,
    const uint8_t iv[const CC20_B2S_SIV_IVLEN],
    const uint8_t nonce[const CHACHA20_NONCELEN],
    uint8_t subkey[const CHACHA20_KEYLEN]
) {
    blake2s_state state = { 0 };
    blake2s_InitKey(&state, CHACHA20_KEYLEN, ctx->enc_key, CHACHA20_KEYLEN);
    blake2s_Update(&state, nonce, CHACHA20_NONCELEN);
    blake2s_Update(&state, iv, CC20_B2S_SIV_IVLEN);
    blake2s_Update(&state, "kdf/sub", 7);
    blake2s_Final(&state, subkey, CHACHA20_KEYLEN);
}

static inline void cc20_b2s_siv_iv(
    const cc20_b2s_ctx_t* const ctx,
    size_t plaintext_len,
    const uint8_t plaintext[const plaintext_len],
    size_t ad_len,
    const uint8_t ad[const ad_len],
    const uint8_t nonce[const CHACHA20_NONCELEN],
    uint8_t iv[const CC20_B2S_SIV_IVLEN]
) {
    uint8_t lengths[16];
    store64_le(lengths, (uint64_t)plaintext_len);
    store64_le(lengths + 8, (uint64_t)ad_len);

    blake2s_state state = { 0 };
    blake2s_InitKey(&state, CC20_B2S_SIV_IVLEN, ctx->mac_key, BLAKE2S_KEYLEN);
    blake2s_Update(&state, lengths, sizeof(lengths));
    blake2s_Update(&state, plaintext, plaintext_len);
    blake2s_Update(&state, ad, ad_len);
    blake2s_Update(&state, nonce, CHACHA20_NONCELEN);
    blake2s_Final(&state, iv, CC20_B2S_SIV_IVLEN);
}

void cc20_b2s_siv_init(
    const uint8_t master_key[const MASTER_KEYLEN], 
    cc20_b2s_ctx_t* const ctx
) {
    const uint8_t ENC_CTX[7] = "kdf/enc";
    const uint8_t MAC_CTX[7] = "kdf/mac";

    blake2s_Key(
        ENC_CTX, 7,
        master_key, MASTER_KEYLEN,
        ctx->enc_key, CHACHA20_KEYLEN
    );

    blake2s_Key(
        MAC_CTX, 7,
        master_key, MASTER_KEYLEN,
        ctx->mac_key, BLAKE2S_KEYLEN
    );
}

cc20_b2s_siv_res_t cc20_b2s_siv_encrypt(
    const cc20_b2s_ctx_t* const ctx,
    size_t plaintext_len,
    const uint8_t plaintext[const plaintext_len],
    size_t ad_len,
    const uint8_t ad[const ad_len],
    const uint8_t nonce[const CHACHA20_NONCELEN],
    uint8_t ciphertext[const plaintext_len], // Out
    uint8_t iv[const CC20_B2S_SIV_IVLEN]     // Out
) {
    if((uint64_t)plaintext_len > ((uint64_t)1 << 38)) 
        return SIV_INVALID_LENGTH;

    // IV
    cc20_b2s_siv_iv(
        ctx,
        plaintext_len, plaintext,
        ad_len, ad,
        nonce, iv
    );

    // Subkey
    uint8_t subkey_buffer[CHACHA20_KEYLEN];
    cc20_b2s_siv_derive_subkey(ctx, iv, nonce, subkey_buffer);

    // Encrypt
    memcpy(ciphertext, plaintext, plaintext_len);
    ChaCha20_Ctx cc20_ctx = { 0 };
    ChaCha20_init(&cc20_ctx, subkey_buffer, nonce, 0);
    ChaCha20_xor(&cc20_ctx, ciphertext, plaintext_len);

    return SIV_OK;
}

cc20_b2s_siv_res_t cc20_b2s_siv_decrypt(
    const cc20_b2s_ctx_t* const ctx,
    size_t ciphertext_len,
    const uint8_t ciphertext[const ciphertext_len],
    size_t ad_len,
    const uint8_t ad[const ad_len],
    const uint8_t nonce[const CHACHA20_NONCELEN],
    const uint8_t iv[const CC20_B2S_SIV_IVLEN],
    uint8_t plaintext[const ciphertext_len] // Out
) {
    if((uint64_t)ciphertext_len > ((uint64_t)1 << 38)) 
        return SIV_INVALID_LENGTH;

    // Subkey
    uint8_t subkey_buffer[CHACHA20_KEYLEN];
    cc20_b2s_siv_derive_subkey(ctx, iv, nonce, subkey_buffer);

    // Decrypt
    memcpy(plaintext, ciphertext, ciphertext_len);
    ChaCha20_Ctx cc20_ctx = { 0 };
    ChaCha20_init(&cc20_ctx, subkey_buffer, nonce, 0);
    ChaCha20_xor(&cc20_ctx, plaintext, ciphertext_len);

    // IV
    uint8_t iv_computed[CC20_B2S_SIV_IVLEN];
    cc20_b2s_siv_iv(
        ctx,
        ciphertext_len, plaintext,
        ad_len, ad,
        nonce, iv_computed
    );

    if(!iv_cmp(iv, iv_computed)) {
        memset(plaintext, 0, ciphertext_len);
        return SIV_VERIFICATION_FAILED;
    }

    return SIV_OK;
}
