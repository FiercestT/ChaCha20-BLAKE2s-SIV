#ifndef CC20_B2S_SIV_TYPES_H
#define CC20_B2S_SIV_TYPES_H

#include "stdint.h"
#include "stddef.h"

#if !defined(CC20_B2S_SIV_128) && !defined(CC20_B2S_SIV_256)
    #define CC20_B2S_SIV_256
#endif

#ifdef CC20_B2S_SIV_128
    #define CC20_B2S_SIV_IVLEN 16
#elif defined(CC20_B2S_SIV_256)
    #define CC20_B2S_SIV_IVLEN 32
#endif

#define MASTER_KEYLEN     (32)
#define CHACHA20_KEYLEN   (32)
#define CHACHA20_NONCELEN (12)
#define BLAKE2S_KEYLEN    (32)

typedef uint8_t cc20_b2s_siv_master_key_t[MASTER_KEYLEN];
typedef uint8_t cc20_b2s_siv_chacha20_key_t[CHACHA20_KEYLEN];
typedef uint8_t cc20_b2s_siv_chacha20_nonce_t[CHACHA20_NONCELEN];
typedef uint8_t cc20_b2s_siv_blake2s_key_t[BLAKE2S_KEYLEN];
typedef uint8_t cc20_b2s_siv_iv_t[CC20_B2S_SIV_IVLEN];

typedef enum cc20_b2s_siv_res_e {
    SIV_OK,
    SIV_INVALID_LENGTH,
    SIV_VERIFICATION_FAILED,
} cc20_b2s_siv_res_t;

typedef struct cc20_b2s_ctx_s {
    cc20_b2s_siv_chacha20_key_t enc_key;
    cc20_b2s_siv_blake2s_key_t mac_key;
} cc20_b2s_ctx_t;

#endif // CC20_B2S_SIV_TYPES_H
