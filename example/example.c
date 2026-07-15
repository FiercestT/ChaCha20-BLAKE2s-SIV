#include "stdint.h"
#include "stdio.h"

#include "cc20_b2s_siv.h"

// Demo Key. Never use this.
const uint8_t MASTER_KEY[MASTER_KEYLEN] = { 0x00, 0x01, 0x02, 0x03, 0 };
uint8_t nonce [CHACHA20_NONCELEN] = { 0 };

int main(void) {
    // Init
    cc20_b2s_ctx_t ctx = { 0 };
    cc20_b2s_siv_init(MASTER_KEY, &ctx);

    // Encrypt
    const uint8_t plaintext[11] = "Hello World"; // Ignore \0.
    const uint8_t ad[2] = "AD"; 
    uint8_t ciphertext[sizeof(plaintext)] = { 0 };
    uint8_t iv[CC20_B2S_SIV_IVLEN] = { 0 };

    cc20_b2s_siv_res_t result = cc20_b2s_siv_encrypt(
        &ctx,
        sizeof(plaintext), plaintext,
        sizeof(ad), ad,
        nonce,
        ciphertext, iv
    );

    // !Increment Nonce after encrypting (each nonce must only be used once under the same key).
    //nonce++;

    if(result != SIV_OK) {
        printf("Encryption failed\n");
        return 1;
    }

    // Decrypt
    uint8_t decrypted[sizeof(plaintext)] = { 0 };

    // Optional: Tamper with the ciphertext. Verification will fail.
    //ciphertext[0] = 0x00;
    
    result = cc20_b2s_siv_decrypt(
        &ctx,
        sizeof(plaintext), ciphertext,
        sizeof(ad), ad,
        nonce, iv,
        decrypted
    );

    switch(result) {
        case SIV_OK:
            break;
        case SIV_VERIFICATION_FAILED:
            printf("Verification failed\n");
        default: 
            printf("Decryption failed (%d)\n", result);
            return 1;
    }

    // Results
    printf("Plaintext [%d]:  %.*s\n", (int)sizeof(plaintext), (int)sizeof(plaintext), plaintext);
    printf("Ciphertext (Hex) [%d]: ", (int)sizeof(ciphertext));
    for(size_t i = 0; i < sizeof(ciphertext); i++) {
        printf("%02x", (unsigned)ciphertext[i]);
    }
    printf("\nIV (Hex) [%d]: ", (int)sizeof(iv));
    for(size_t i = 0; i < sizeof(iv); i++) {
        printf("%02x", (unsigned)iv[i]);
    }
    printf("\nDecrypted [%d]: %.*s\n", (int)sizeof(decrypted), (int)sizeof(decrypted), decrypted);

    return 0;
}
