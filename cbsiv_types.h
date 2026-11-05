#ifndef CBSIV_TYPES_H
#define CBSIV_TYPES_H

#include "stdint.h"
#include "stddef.h"

#if !defined(CBSIV_128) && !defined(CBSIV_256)
    #define CBSIV_256
#endif

#ifdef CBSIV_128
    #define CBSIV_IVLEN 16
#elif defined(CBSIV_256)
    #define CBSIV_IVLEN 32
#endif

#define CBSIV_MASTER_KEYLEN    (32)
#define CBSIV_CHACHA20_KEYLEN   (32)
#define CBSIV_CHACHA20_NONCELEN (12)
#define CBSIV_BLAKE2S_KEYLEN    (32)

typedef uint8_t cbsiv_master_key_t[CBSIV_MASTER_KEYLEN];
typedef uint8_t cbsiv_chacha20_key_t[CBSIV_CHACHA20_KEYLEN];
typedef uint8_t cbsiv_chacha20_nonce_t[CBSIV_CHACHA20_NONCELEN];
typedef uint8_t cbsiv_blake2s_key_t[CBSIV_BLAKE2S_KEYLEN];
typedef uint8_t cbsiv_iv_t[CBSIV_IVLEN];

typedef enum cbsiv_res_e {
    CBSIV_OK,
    CBSIV_INVALID_LENGTH,
    CBSIV_VERIFICATION_FAILED,
} cbsiv_res_t;

typedef struct cbsiv_ctx_s {
    cbsiv_chacha20_key_t enc_key;
    cbsiv_blake2s_key_t mac_key;
} cbsiv_ctx_t;

#endif // CBSIV_TYPES_H
