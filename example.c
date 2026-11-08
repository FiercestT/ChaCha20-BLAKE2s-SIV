#include "stdint.h"
#include "stdio.h"
#include "string.h"
#include "cbsiv.h"

// Demo Key. Never use this.
const cbsiv_master_key_t MASTER_KEY = { 0x00, 0x01, 0x02, 0x03, 0 };
cbsiv_chacha20_nonce_t nonce = { 0 };

int main(void) {
    // Init
    cbsiv_ctx_t ctx = { 0 };
    cbsiv_init(&ctx, MASTER_KEY);

    // Encrypt
    __attribute__((nonstring)) const uint8_t plaintext[11] = "Hello World";
    __attribute__((nonstring)) const uint8_t ad[2] = "AD"; 
    uint8_t ciphertext[sizeof(plaintext)] = { 0 };
    cbsiv_iv_t iv = { 0 };
    cbsiv_chacha20_nonce_t message_nonce;

    memcpy(message_nonce, nonce, sizeof(nonce));
    cbsiv_res_t result = cbsiv_encrypt(&ctx, nonce, sizeof(plaintext), plaintext, sizeof(ad), ad, ciphertext, iv);

    // Increment nonce after encrypting. Each nonce should be used only once per key.
    cbsiv_increment_nonce(nonce, 1);

    if(result != CBSIV_OK) {
        printf("Encryption failed\n");
        return 1;
    }

    // Decrypt
    uint8_t decrypted[sizeof(plaintext)] = { 0 };

    // Optional: Tamper with the ciphertext. Verification will fail.
    //ciphertext[0] = 0x00;
    
    result = cbsiv_decrypt(&ctx, message_nonce, iv, sizeof(plaintext), ciphertext, sizeof(ad), ad, decrypted);

    switch(result) {
        case CBSIV_OK:
            break;
        case CBSIV_VERIFICATION_FAILED:
            printf("Verification failed\n");
            return 1;
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
