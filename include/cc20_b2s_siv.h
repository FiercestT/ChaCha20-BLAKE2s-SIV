#ifndef CC20_B2S_SIV_H
#define CC20_B2S_SIV_H

#include "cc20_b2s_siv_types.h"
#include "stddef.h"

/**
 * @brief Initialize the IV context by deriving keys from the master key.
 * 
 * @param master_key The master key to derive keys from.
 * @param ctx The context stores the subkeys.
 */
void cc20_b2s_siv_init(
    const uint8_t master_key[const MASTER_KEYLEN], 
    cc20_b2s_ctx_t* const ctx
);

/**
 * @brief Encrypt a plaintext and authenticate associated data using the ChaCha20-Blake2s-SIV mode.
 * 
 * @param ctx The key context.
 * @param plaintext_len Bytelen of plaintext. 
 * @param plaintext Plaintext Bytes.
 * @param ad_len Bytelen of associated data.
 * @param ad Associated data (does not get encrypted, but is authenticated).
 * @param nonce 96-bit Number used once, must not repeat. This value is also authenticated. It can be freely stored/transmitted.
 * @param ciphertext The output ciphertext, will be the same length as the plaintext. 
 * @param iv The output IV (Mac/Tag) that must be stored/transmitted with the ciphertext to provide authentication.
 * @return cc20_b2s_siv_res_t 
 *          SIV_INVALID_LENGTH: If the plaintext_len is > 2^38 (max counter of IETF ChaCha20)
 *          SIV_OK: Ok
 */
cc20_b2s_siv_res_t cc20_b2s_siv_encrypt(
    const cc20_b2s_ctx_t* const ctx,
    size_t plaintext_len,
    const uint8_t plaintext[const plaintext_len],
    size_t ad_len,
    const uint8_t ad[const ad_len],
    const uint8_t nonce[const CHACHA20_NONCELEN],
    uint8_t ciphertext[const plaintext_len], // Out
    uint8_t iv[const CC20_B2S_SIV_IVLEN]     // Out
);

/**
 * @brief Decrypt a ciphertext and verify the associated data using the ChaCha20-Blake2s-SIV mode.
 * 
 * @param ctx The key context.
 * @param ciphertext_len Bytelen of ciphertext.
 * @param ciphertext Ciphertext bytes.
 * @param ad_len Bytelen of associated data.
 * @param ad Associated data.
 * @param nonce 96-bit Number used once, the same one used to encrypt this message and transmitted/stored with it.
 * @param iv The stored/received IV that will be used to verify the message.
 * @param plaintext The output plaintext if the message successfully authenticates. 
 * @return cc20_b2s_siv_res_t 
 *          SIV_INVALID_LENGTH: If the cipher_len is > 2^38 (max counter of IETF ChaCha20)
 *          SIV_VERIFICATION_FAILED: If the IV fails to authenticate, discard this message, it was either corrupted or tampered.
 *          SIV_OK: Ok
 */
cc20_b2s_siv_res_t cc20_b2s_siv_decrypt(
    const cc20_b2s_ctx_t* const ctx,
    size_t ciphertext_len,
    const uint8_t ciphertext[const ciphertext_len],
    size_t ad_len,
    const uint8_t ad[const ad_len],
    const uint8_t nonce[const CHACHA20_NONCELEN],
    const uint8_t iv[const CC20_B2S_SIV_IVLEN],
    uint8_t plaintext[const ciphertext_len] // Out
);

#endif // CC20_B2S_SIV_H
