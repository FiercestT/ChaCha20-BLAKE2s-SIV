#ifndef CBSIV_H
#define CBSIV_H

#include "cbsiv_types.h"

/**
 * @brief Derive encryption and MAC keys from a master key.
 *
 * @param master_key [CBSIV_MASTER_KEYLEN] The master key.
 * @param ctx The key context to initialize. Does not need to be zeroed before init.
 */
void cbsiv_init(
    const cbsiv_master_key_t master_key,
    cbsiv_ctx_t* ctx
);

/**
 * @brief Add a value to a 96-bit little-endian nonce.
 * Overflow wraps modulo 2^96.
 *
 * @param nonce [CBSIV_CHACHA20_NONCELEN] The nonce buffer to update.
 * @param n The value to add.
 */
void cbsiv_increment_nonce(
    cbsiv_chacha20_nonce_t nonce,
    uint32_t n
);

/**
 * @brief Encrypt plaintext and authenticate unencrypted data with ChaCha20-BLAKE2s-SIV.
 *        Set plaintext = ciphertext for in place encryption.
 *
 * @param ctx The initialized key context.
 * @param plaintext_len Byte length of the plaintext input.
 * @param plaintext [plaintext_len] The plaintext input buffer.
 * @param ad_len Byte length of the unencrypted, authenticated data.
 * @param ad [ad_len] The unencrypted, authenticated data buffer.
 * @param nonce [CBSIV_CHACHA20_NONCELEN] The authenticated nonce. Use a unique nonce per message.
 * @param ciphertext [plaintext_len] The ciphertext output buffer.
 * @param iv [CBSIV_IVLEN] The authentication IV output buffer. Store or transmit with the ciphertext.
 * @return CBSIV_OK on success or CBSIV_INVALID_LENGTH if the input exceeds 2^38 bytes and will cause a counter overflow.
 */
cbsiv_res_t cbsiv_encrypt(
    const cbsiv_ctx_t* ctx,
    size_t plaintext_len,
    const uint8_t* plaintext,
    size_t ad_len,
    const uint8_t* ad,
    const cbsiv_chacha20_nonce_t nonce,
    uint8_t* ciphertext,
    cbsiv_iv_t iv
);

/**
 * @brief Decrypt ciphertext and verify authenticated data with ChaCha20-BLAKE2s-SIV.
 *        Set ciphertext = plaintext for in place decryption.
 *
 * @param ctx The initialized key context.
 * @param ciphertext_len Byte length of the ciphertext input.
 * @param ciphertext [ciphertext_len] The ciphertext input buffer.
 * @param ad_len Byte length of the unencrypted, authenticated data.
 * @param ad [ad_len] The unencrypted, authenticated data buffer.
 * @param nonce [CBSIV_CHACHA20_NONCELEN] The nonce used for encryption.
 * @param iv [CBSIV_IVLEN] The authentication IV to verify.
 * @param plaintext [ciphertext_len] The plaintext output buffer. Zeroed if IV verification fails.
 * @return CBSIV_OK on success, CBSIV_VERIFICATION_FAILED if IV verification fails, or CBSIV_INVALID_LENGTH if the input exceeds 2^38 bytes and will cause a counter overflow.
 */
cbsiv_res_t cbsiv_decrypt(
    const cbsiv_ctx_t* ctx,
    size_t ciphertext_len,
    const uint8_t* ciphertext,
    size_t ad_len,
    const uint8_t* ad,
    const cbsiv_chacha20_nonce_t nonce,
    const cbsiv_iv_t iv,
    uint8_t* plaintext
);

#endif // CBSIV_H
