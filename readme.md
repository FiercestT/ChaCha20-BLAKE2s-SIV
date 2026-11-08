# ChaCha20-BLAKE2s-SIV

A C implementation of a Nonce Synthetic Initialization Vector (NSIV) AEAD using ChaCha20 and BLAKE2s from [ChaChaSlide](https://github.com/FiercestT/ChaChaSlide).

This specific construction is not independently reviewed or proven secure. 

## Construction

### Modes
- cbsiv-128: ChaCha20-BLAKE2s-SIV with 128-bit IV Tag.
- cbsiv-256: ChaCha20-BLAKE2s-SIV with 256-bit IV Tag.

### Parameters
| In/Out | Parameter            | Size                 | Description                                                                                                                                                               |
|--------|----------------------|----------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| In     | Master Key           | 256-bits             | The master key that derives `mac_key` and `enc_key`.                                                                                                                      |
| In     | Nonce                | 96-bits              | A number used once. Automatically included as AD. Must be unique, reuse under the same master key can reveal message equiality of ciphertexts. Can be safely transmitted. |
| In     | Associated Data (AD) | AD_Len bytes         | Unencrypted, authenticated data. Can be safely transmitted.                                                                                                               |
| In     | Plaintext            | Plaintext_Len bytes  | Data to be encrypted, authenticated.                                                                                                                                      |
| Out    | Ciphertext           | Plaintext_Len bytes  | Encrypted, authenticated data. Can be safely transmitted.                                                                                                                 |
| Out    | IV                   | 128-bits or 256-bits | The IV Tag. Authenticates the ciphertext and AD. Size is selectable.                                                                                                      |

Notes:
- Security Properties: Confidentiality, Integrity, Authenticity, Misuse Resistant Authenticated Encryption (MRAE), Key Committing.
- Uses BLAKE2s as a KDF with the IV as context. The resulting subkey will be used as the ChaCha20 key.
- This differs from traditional SIV where the IV itself would be used as the ChaCha20 nonce. That would not be possible as ChaCha20 uses a small 96-bit nonce. 
- This design is intended for inexpensive embedded use and pure software implementation. It is more optimized for size than speed.
- The intended transmission/stored/shared data should be (ad | nonce | ciphertext | iv).
- In SIV construction, the term IV is used instead of "MAC" or "Tag", but the purpose is the same.
- The encryption key is included in the IV. Providing key commitment.

## Pseudocode

<details>

```c
// | = concatenation
// uint64 lengths are encoded little-endian
// KDF labels do not include a terminating NUL byte

if defined(CBSIV_128)
    MAC_SIZE = 16
else
    MAC_SIZE = 32

// Compute subkeys based on the master key once.
function cbsiv_init(
    master_key[32]
) {
    // KDF
    enc_key[32] = blake2s(
        key: master_key
        input: "kdf/enc"
        digest_length: 32
    )

    // KDF
    mac_key[32] = blake2s(
        key: master_key
        input: "kdf/mac"
        digest_length: 32
    )
    
    return enc_key, mac_key
}

function cbsiv_encrypt(
    enc_key[32]
    mac_key[32]
    nonce[12]
    plaintext[plaintext_len]
    ad[ad_len]
) {
    if(plaintext_len > (2^32 * 64))
        return "Plaintext too large."

    IV[MAC_SIZE] = blake2s( 
        key: mac_key, 
        input: enc_key | (uint64)plaintext_len | (uint64)ad_len | plaintext | ad | nonce
        digest: MAC_SIZE
    )

    enc_subkey[32] = blake2s(
        key: enc_key, 
        input: nonce | IV | "kdf/sub",
        digest: 32
    )

    ciphertext[plaintext_len] = chacha20(
        key: enc_subkey, 
        input: plaintext, 
        nonce: nonce,
        counter: 0
    )

    return ciphertext | IV
}

function decrypt(
    enc_key[32]
    mac_key[32]
    nonce[12]
    IV[MAC_SIZE]
    ciphertext[ciphertext_len]
    ad[ad_len]
) {
    if(ciphertext_len > (2^32 * 64))
        return "Ciphertext too large."

    enc_subkey[32] = blake2s(
        key: enc_key, 
        input: nonce | IV | "kdf/sub",
        digest: 32
    )

    plaintext[ciphertext_len] = chacha20(
        key: enc_subkey, 
        input: plaintext, 
        nonce: nonce,
        counter: 0
    )

    IV_Computed[MAC_SIZE] = blake2s( 
        key: mac_key, 
        input: enc_key | (uint64)ciphertext_len | (uint64)ad_len | plaintext | ad | nonce
        digest: MAC_SIZE
    )


    if(IV != IV_Computed) {
        zero(plaintext)
        return "Authentication Failed"
    }
    
    return plaintext
}
```
</details>

## Usage
- Initialize ChaChaSlide with `git submodule update --init --recursive`. Use `git submodule update --remote lib/ChaChaSlide` to update it.
- Add the repository root and /lib/ChaChaSlide/include to the include path.
- Add /cbsiv.c, /lib/ChaChaSlide/src/ccs_chacha.c, and /lib/ChaChaSlide/src/ccs_blake2.c to your target. Keep `CCS_CC_IETF` and `CCS_B2S` enabled.
- If you want to use the 128-bit IV, build with `CBSIV_128` defined for the library and its callers.It will use 256-bit if not defined.
- With CMake, link to `cbsiv_128` or `cbsiv_256`. `Release` uses -O3, `MinSizeRel` uses -Os, and LTO is disabled by default. Enable it with `-DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON`.
- See `example.c` for usage.

## Primitive Implementations Used
- ChaCha20: IETF ChaCha20 from https://github.com/FiercestT/ChaChaSlide.
- BLAKE2s: Keyed BLAKE2s from https://github.com/FiercestT/ChaChaSlide.

## Tests

Testing suite is available in test/functional.c. Targets are available for both 128 and 256-bit variants.

## Code Size

Library only. All public functions retained. Totals exclude metadata, headers, unwind. cbsiv-256. No LTO.

#### Arm Cortex-M3

GCC 13.4.0. 

| Optimization | .text | .rodata | .bss | Total |
|--------------|------:|--------:|-----:|------:|
| -Os | 1,780 B | 136 B | 0 B | 1,916 B |
| -O3 | 7,480 B | 56 B | 0 B | 7,536 B |

#### Windows x86-64

GCC 16.1.0 (MSYS2). 

| Optimization | .text | .rdata | .bss | Total |
|--------------|------:|-------:|-----:|------:|
| -Os | 2,608 B | 192 B | 0 B | 2,800 B |
| -O3 | 8,768 B | 144 B | 0 B | 8,912 B |

#### Linux x86-64

GCC 14.2.0 (Debian under WSL).

| Optimization | .text | .rodata | .bss | Total |
|--------------|------:|--------:|-----:|------:|
| -Os | 2,496 B | 112 B | 0 B | 2,608 B |
| -O3 | 8,345 B | 112 B | 0 B | 8,457 B |

## Benchmark

9800X3D. GCC 16.1 MSYS2 on Windows 11. No LTO. cbsiv-256.

associated data=32B for all operations

| Operation | Plaintext size | Throughput -O3 | Throughput -Os |
|---|---:|---:|---:|
| encrypt | 16 B | 29.40 MiB/s | 11.80 MiB/s |
| decrypt/verify success | 16 B | 29.73 MiB/s | 11.73 MiB/s |
| decrypt/verify failed | 16 B | 29.58 MiB/s | 11.74 MiB/s |
| encrypt | 64 B | 102.08 MiB/s | 40.38 MiB/s |
| decrypt/verify success | 64 B | 101.17 MiB/s | 40.58 MiB/s |
| decrypt/verify failed | 64 B | 99.95 MiB/s | 40.22 MiB/s |
| encrypt | 256 B | 259.85 MiB/s | 98.93 MiB/s |
| decrypt/verify success | 256 B | 259.84 MiB/s | 99.25 MiB/s |
| decrypt/verify failed | 256 B | 253.84 MiB/s | 95.01 MiB/s |
| encrypt | 1 KiB | 423.31 MiB/s | 158.39 MiB/s |
| decrypt/verify success | 1 KiB | 421.99 MiB/s | 158.11 MiB/s |
| decrypt/verify failed | 1 KiB | 402.01 MiB/s | 152.41 MiB/s |
| encrypt | 4 KiB | 493.59 MiB/s | 182.54 MiB/s |
| decrypt/verify success | 4 KiB | 492.16 MiB/s | 184.62 MiB/s |
| decrypt/verify failed | 4 KiB | 479.34 MiB/s | 177.78 MiB/s |
| encrypt | 16 KiB | 529.05 MiB/s | 191.73 MiB/s |
| decrypt/verify success | 16 KiB | 529.30 MiB/s | 191.57 MiB/s |
| decrypt/verify failed | 16 KiB | 498.41 MiB/s | 185.59 MiB/s |
| encrypt | 64 KiB | 527.52 MiB/s | 190.58 MiB/s |
| decrypt/verify success | 64 KiB | 536.92 MiB/s | 194.62 MiB/s |
| decrypt/verify failed | 64 KiB | 498.57 MiB/s | 188.27 MiB/s |
| encrypt | 256 KiB | 528.11 MiB/s | 194.17 MiB/s |
| decrypt/verify success | 256 KiB | 525.29 MiB/s | 185.97 MiB/s |
| decrypt/verify failed | 256 KiB | 510.99 MiB/s | 181.31 MiB/s |
| encrypt | 1 MiB | 538.15 MiB/s | 194.40 MiB/s |
| decrypt/verify success | 1 MiB | 536.32 MiB/s | 194.61 MiB/s |
| decrypt/verify failed | 1 MiB | 506.59 MiB/s | 183.91 MiB/s |
