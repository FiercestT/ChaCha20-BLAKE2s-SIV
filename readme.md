# ChaCha20-BLAKE2s-SIV

A C implementation of a Synthetic Initialization Vector (SIV) construction using ChaCha20 and BLAKE2s.

This repo is not independently reviewed or proven secure. Use at your own risk.

## Construction

Modes:
- cc20-b2s-siv-128: ChaCha20-BLAKE2s-SIV with 128-bit IV Tag.
- cc20-b2s-siv-256: ChaCha20-BLAKE2s-SIV with 256-bit IV Tag.

Input:
- Key[256b]: A master key from which subkeys are derived from.
- Plaintext[Any]: The plaintext to encrypt.
- Nonce[96b]: A number used once (recommended monotonic), should be unique or message equality can be determined under reuse. Can be safely transmitted.
- Associated Data - AD[Any]: Any unencrypted associated data that is authenticated. Can be safely transmitted.

Output:
- Ciphertext[Plaintext_Len]: The encrypted ciphertext.
- IV[256b or 128b]: The IV/MAC/Tag (same meaning in this case) that authenticates the ciphertext. Selectable between 256b and 128b depending on the used mode. This is the BLAKE2s digest size, not truncated.

Idea:
- Build a ChaCha20-BLAKE2s SIV based mode of AEAD.
- Use BLAKE2s as a subkey KDF for ChaCha20 as opposed to using XChaCha20 while still accomplishing an extended nonce to fit the IV (the speed was not compared, it was a design choice to use the existing BLAKE2s for key derivation instead of implementing HChaCha20).
- This design is intended for inexpensive embedded use and pure software implementation. It is more optimized for size than speed.

Notes:
- Based on IETF ChaCha20 (32-bit block counter - not the 64-bit variant proposed by D.J. Bernstein), with the counter starting at 0.
- In SIV construction, the term IV is used instead of "MAC" or "Tag", but the purpose is the same.
- The intended transmission/stored/shared data should be (ad | nonce | ciphertext | iv).

EtM vs SIV:
- In EtM (Encrypt then MAC) modes, nonce reuse under one key causes keystream reuse, and can be used to decrypt ciphertexts if another plaintext is known. Confidentiality is fully lost.
- In SIV (Synthetic Initialization Vector) modes, nonce reuse under one key will only reveal plaintext equality, but different plaintexts cannot be decrypted. 
- EtM is generally slightly faster than SIV on average since a MAC/Tag verification can be performed before the more expensive decryption operation, whereas SIV must decrypt before verifying every time.
- As a result, SIV constructions can retain confidentiality under nonce reuse at the cost of always requiring decryption before verification and complexity.

## Psuedocode 

```c
// b = bit
// B = Byte
// | = concatenation

ifdef (CC20_B2S_SIV_128)
    MAC_SIZE = 16B
ifdef (CC20_B2S_SIV_256)
    MAC_SIZE = 32B

MASTER_KEY[256b]

// Compute subkeys based on the master key once.
func init():
    enc_key[256b] = blake2s( // KDF
        key: MASTER_KEY
        input: "kdf/enc"
        digest: 32B
    )
    mac_key[256b] = blake2s( // KDF
        key: MASTER_KEY
        input: "kdf/mac"
        digest: 32B
    )
    return enc_key, mac_key

func encrypt(
    enc_key[256b]
    mac_key[256b]
    plaintext[Any]
    nonce[96b]
    ad[Any]
) {
    if(len(ciphertext) > 1 << 38)
        return "Plaintext too large."

    IV = blake2s_mac( // MAC
        key: mac_key, 
        input: (uint64)len(plaintext) | (uint64)len(ad) | plaintext | ad | nonce
        digest: MAC_SIZE
    )

    enc_subkey = blake2s( // KDF
        key: enc_key, 
        input: nonce | IV | "kdf/sub",
        digest: 32B
    )

    ciphertext = chacha20(
        key: enc_subkey, 
        input: plaintext, 
        nonce: nonce
    )

    return ciphertext | IV
}

func decrypt(
    enc_key[256b]
    mac_key[256b]
    ciphertext[Any]
    nonce[96b]
    ad[Any]
    IV[MAC_SIZE]
) {
    if(len(ciphertext) > 1 << 38)
        return "Plaintext too large."

    enc_subkey = blake2s( // KDF
        key: enc_key, 
        input: nonce | IV | "kdf/sub", 
        digest: 32B
    )

    plaintext = chacha20(
        key: enc_subkey, 
        input: ciphertext, 
        nonce: nonce
    )

    IV_Computed = blake2s( // MAC
        key: mac_key, 
        input: (uint64)len(ciphertext) | (uint64)len(ad) | plaintext | ad | nonce
        digest: MAC_SIZE
    )

    if(IV != IV_Computed) // Use constant time
        return "Authentication Failed"
    
    return plaintext
}
```

## Usage
- Add /include to the include path. 
- Add /src to your target.
- Add /lib to your include path and its .c files to your target.
- If you want to use the 128-bit IV, build with CC20_B2S_SIV_128 defined, it will use 256-bit if not defined.
- See /example/example.c for library usage.

## Primitive Implementations Used
- ChaCha20: Slightly modified from https://github.com/marcizhu/ChaCha20 (Quarter round macros were turned into inline functions for space saving).
- BLAKE2s: Slightly modified reference implementation from https://github.com/BLAKE2/BLAKE2 (Unused code was cut for space savings).

## Code Size
When compiled for ARM M3. Library only (/src, /include, /lib). cc20-b2s-siv-256.

| Optimization | .text   | .rodata | .bss | Total   |
|--------------|---------|---------|------|---------|
| -Os          | 3,234 B | 198 B   | 0 B  | 3,432 B |
| -O3          | 7,036 B | 184 B   | 0 B  | 7,220 B |

## Tests

Testing suite is available in test/functional.c. Targets are available for both 128 and 256-bit variants.

## Benchmark

With -O3 on a 9800X3D. No explicit SIMD/Vector optimizations (ref impl.) Single thread and hot cache. gcc 16.1 MSYS2 on Windows 11. 

cc20-b2s-siv-256 benchmark (approx.)
```
associated data=32B for all operations
OPERATION            PLAINTEXT SIZE              TIME        THROUGHPUT
initialize                      0 B       0.510 us/op                  
encrypt                         0 B       0.540 us/op                  
decrypt/verify success          0 B       0.540 us/op                  
decrypt/bad tag                 0 B       0.540 us/op                  
encrypt                        16 B       0.710 us/op       21.49 MiB/s
decrypt/verify success         16 B       0.700 us/op       21.80 MiB/s
decrypt/bad tag                16 B       0.720 us/op       21.19 MiB/s
decrypt/bad ciphertext         16 B       0.720 us/op       21.19 MiB/s
encrypt                        64 B       0.720 us/op       84.77 MiB/s
decrypt/verify success         64 B       0.720 us/op       84.77 MiB/s
decrypt/bad tag                64 B       0.740 us/op       82.48 MiB/s
decrypt/bad ciphertext         64 B       0.750 us/op       81.38 MiB/s
encrypt                       256 B       1.373 us/op      177.78 MiB/s
decrypt/verify success        256 B       1.450 us/op      168.42 MiB/s
decrypt/bad tag               256 B       1.450 us/op      168.42 MiB/s
decrypt/bad ciphertext        256 B       1.404 us/op      173.91 MiB/s
encrypt                       1 KiB       4.089 us/op      238.81 MiB/s
decrypt/verify success        1 KiB       4.028 us/op      242.42 MiB/s
decrypt/bad tag               1 KiB       3.906 us/op      250.00 MiB/s
decrypt/bad ciphertext        1 KiB       4.028 us/op      242.42 MiB/s
encrypt                       4 KiB      15.137 us/op      258.06 MiB/s
decrypt/verify success        4 KiB      12.451 us/op      313.73 MiB/s
decrypt/bad tag               4 KiB      12.939 us/op      301.89 MiB/s
decrypt/bad ciphertext        4 KiB      12.695 us/op      307.69 MiB/s
encrypt                      16 KiB      53.711 us/op      290.91 MiB/s
decrypt/verify success       16 KiB      53.711 us/op      290.91 MiB/s
decrypt/bad tag              16 KiB      51.758 us/op      301.89 MiB/s
decrypt/bad ciphertext       16 KiB      49.805 us/op      313.73 MiB/s
encrypt                      64 KiB     199.219 us/op      313.73 MiB/s
decrypt/verify success       64 KiB     199.219 us/op      313.73 MiB/s
decrypt/bad tag              64 KiB     207.031 us/op      301.89 MiB/s
decrypt/bad ciphertext       64 KiB     203.125 us/op      307.69 MiB/s
encrypt                     256 KiB     796.875 us/op      313.73 MiB/s
decrypt/verify success      256 KiB     828.125 us/op      301.89 MiB/s
decrypt/bad tag             256 KiB     781.250 us/op      320.00 MiB/s
decrypt/bad ciphertext      256 KiB     812.500 us/op      307.69 MiB/s
encrypt                       1 MiB    3250.000 us/op      307.69 MiB/s
decrypt/verify success        1 MiB    3450.000 us/op      289.86 MiB/s
decrypt/bad tag               1 MiB    3150.000 us/op      317.46 MiB/s
decrypt/bad ciphertext        1 MiB    3100.000 us/op      322.58 MiB/s
```
