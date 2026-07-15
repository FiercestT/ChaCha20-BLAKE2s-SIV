#ifndef CC20_B2S_SIV_TYPES_H
#define CC20_B2S_SIV_TYPES_H

#include "stdint.h"

#if !defined(CC20_B2S_SIV_128) && !defined(CC20_B2S_SIV_256)
    #define CC20_B2S_SIV_256
#endif

#ifdef CC20_B2S_SIV_128
    #define CC20_B2S_SIV_IVLEN 16
#elif defined(CC20_B2S_SIV_256)
    #define CC20_B2S_SIV_IVLEN 32
#endif

#define MASTER_KEYLEN 32
#define CHACHA20_KEYLEN 32
#define CHACHA20_NONCELEN 12
#define BLAKE2S_KEYLEN 32

typedef enum cc20_b2s_siv_res_e {
    SIV_OK,
    SIV_INVALID_LENGTH,
    SIV_VERIFICATION_FAILED,
} cc20_b2s_siv_res_t;

typedef struct cc20_b2s_ctx_s {
    uint8_t enc_key[CHACHA20_KEYLEN];  
    uint8_t mac_key[BLAKE2S_KEYLEN];
} cc20_b2s_ctx_t;

#endif // CC20_B2S_SIV_TYPES_H
