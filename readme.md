# ChaCha20-BLAKE2s-SIV

A C implementation of a Synthetic Initialization Vector (SIV) AEAD using ChaCha20 and BLAKE2s from [ChaChaSlide](https://github.com/FiercestT/ChaChaSlide).

This repo is not independently reviewed or proven secure. 

## Construction

Modes:
- cbsiv-128: ChaCha20-BLAKE2s-SIV with 128-bit IV Tag.
- cbsiv-256: ChaCha20-BLAKE2s-SIV with 256-bit IV Tag.

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
- Based on IETF ChaCha20 (32-bit block counter - not the 64-bit variant by D.J. Bernstein), with the counter starting at 0.
- In SIV construction, the term IV is used instead of "MAC" or "Tag", but the purpose is the same.
- The intended transmission/stored/shared data should be (ad | nonce | ciphertext | iv).
- The IV's MAC input includes the 32-byte encryption key, binding the tag to both derived keys, including for empty messages. This is intended to provide key commitment.

EtM vs SIV:
- In EtM (Encrypt then MAC) modes, nonce reuse under one key causes keystream reuse, and can be used to decrypt ciphertexts if another plaintext is known. Confidentiality is fully lost.
- In SIV (Synthetic Initialization Vector) modes, nonce reuse under one key will only reveal plaintext equality, but different plaintexts cannot be decrypted. 
- EtM is generally slightly faster than SIV on average since a MAC/Tag verification can be performed before the more expensive decryption operation, whereas SIV must decrypt before verifying every time.
- As a result, SIV constructions can retain confidentiality under nonce reuse at the cost of always requiring decryption before verification and complexity.

## Pseudocode

<details>

```c
// b = bit
// B = Byte
// | = concatenation
// uint64 lengths are encoded little-endian
// KDF labels do not include a terminating NUL byte

ifdef (CBSIV_128)
    MAC_SIZE = 16B
ifdef (CBSIV_256)
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
    if(len(plaintext) > 1 << 38)
        return "Plaintext too large."

    IV = blake2s_mac( // MAC
        key: mac_key, 
        input: enc_key | (uint64)len(plaintext) | (uint64)len(ad) | plaintext | ad | nonce
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
        nonce: nonce,
        counter: 0
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
        nonce: nonce,
        counter: 0
    )

    IV_Computed = blake2s( // MAC
        key: mac_key, 
        input: enc_key | (uint64)len(ciphertext) | (uint64)len(ad) | plaintext | ad | nonce
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
- With CMake, link to `cbsiv_128` or `cbsiv_256`. `Release` uses -O3, `MinSizeRel` uses -Os, and LTO is disabled.
- See `example.c` for library usage.

## Primitive Implementations Used
- ChaCha20: IETF ChaCha20 from https://github.com/FiercestT/ChaChaSlide.
- BLAKE2s: Keyed BLAKE2s from https://github.com/FiercestT/ChaChaSlide.

## Code Size

When compiled for ARM Cortex-M3 (Thumb), GCC 13.4.0, no LTO. Library only, including required ChaChaSlide code and linked helpers, with all public functions retained and unused sections removed. cbsiv-256. No startup/debug metadata; .data is 0 B.

| Optimization | .text   | .rodata | .bss | Total   |
|--------------|---------|---------|------|---------|
| -Os          | 1,776 B | 136 B   | 0 B  | 1,912 B |
| -O3          | 7,480 B | 56 B    | 0 B  | 7,536 B |

## Tests

Testing suite is available in test/functional.c. Targets are available for both 128 and 256-bit variants.

## Benchmark

With -O3 on a 9800X3D. No handwritten SIMD/assembly, no LTO. Single thread and hot cache. GCC 16.1 MSYS2 on Windows 11. Median of three sequential runs, timed with QueryPerformanceCounter.

cbsiv-256 benchmark (approx.)
```
associated data=32B for all operations
OPERATION            PLAINTEXT SIZE              TIME        THROUGHPUT
initialize                      0 B       0.328 us/op
encrypt                         0 B       0.460 us/op
decrypt/verify success          0 B       0.455 us/op
decrypt/bad tag                 0 B       0.458 us/op
encrypt                        16 B       0.510 us/op       29.93 MiB/s
decrypt/verify success         16 B       0.510 us/op       29.91 MiB/s
decrypt/bad tag                16 B       0.516 us/op       29.58 MiB/s
decrypt/bad ciphertext         16 B       0.514 us/op       29.69 MiB/s
encrypt                        64 B       0.593 us/op      102.88 MiB/s
decrypt/verify success         64 B       0.596 us/op      102.42 MiB/s
decrypt/bad tag                64 B       0.612 us/op       99.68 MiB/s
decrypt/bad ciphertext         64 B       0.624 us/op       97.83 MiB/s
encrypt                       256 B       0.943 us/op      258.99 MiB/s
decrypt/verify success        256 B       0.942 us/op      259.05 MiB/s
decrypt/bad tag               256 B       0.966 us/op      252.60 MiB/s
decrypt/bad ciphertext        256 B       0.958 us/op      254.93 MiB/s
encrypt                       1 KiB       2.354 us/op      414.87 MiB/s
decrypt/verify success        1 KiB       2.298 us/op      425.00 MiB/s
decrypt/bad tag               1 KiB       2.406 us/op      405.83 MiB/s
decrypt/bad ciphertext        1 KiB       2.401 us/op      406.78 MiB/s
encrypt                       4 KiB       7.733 us/op      505.17 MiB/s
decrypt/verify success        4 KiB       7.766 us/op      502.99 MiB/s
decrypt/bad tag               4 KiB       8.148 us/op      479.39 MiB/s
decrypt/bad ciphertext        4 KiB       8.108 us/op      481.76 MiB/s
encrypt                      16 KiB      29.609 us/op      527.71 MiB/s
decrypt/verify success       16 KiB      29.397 us/op      531.52 MiB/s
decrypt/bad tag              16 KiB      30.949 us/op      504.86 MiB/s
decrypt/bad ciphertext       16 KiB      30.770 us/op      507.80 MiB/s
encrypt                      64 KiB     116.909 us/op      534.61 MiB/s
decrypt/verify success       64 KiB     115.861 us/op      539.44 MiB/s
decrypt/bad tag              64 KiB     122.678 us/op      509.46 MiB/s
decrypt/bad ciphertext       64 KiB     122.322 us/op      510.95 MiB/s
encrypt                     256 KiB     465.813 us/op      536.70 MiB/s
decrypt/verify success      256 KiB     460.914 us/op      542.40 MiB/s
decrypt/bad tag             256 KiB     486.727 us/op      513.64 MiB/s
decrypt/bad ciphertext      256 KiB     491.453 us/op      508.70 MiB/s
encrypt                       1 MiB    1850.514 us/op      540.39 MiB/s
decrypt/verify success        1 MiB    1854.359 us/op      539.27 MiB/s
decrypt/bad tag               1 MiB    1968.295 us/op      508.05 MiB/s
decrypt/bad ciphertext        1 MiB    1954.113 us/op      511.74 MiB/s
```
