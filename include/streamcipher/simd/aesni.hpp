// AES-NI hardware acceleration — x86_64 AES New Instructions
//
// Wraps the Intel AES-NI instruction set (_mm_aesenc_si128 etc.)
// for single-round encryption with zero software overhead.

#pragma once

#include "streamcipher/simd/simd.hpp"
#include <cstdint>
#include <cstddef>
#include <span>

#ifdef STREAMCIPHER_AESNI
#include <wmmintrin.h>   // AES-NI intrinsics
#include <emmintrin.h>   // SSE2
#endif

namespace streamcipher::simd::aesni {

// ── Single-Round Operations ─────────────────────────────────

/// Perform one AES encryption round: SubBytes + ShiftRows + MixColumns + AddRoundKey.
/// Hardware-accelerated on x86_64; falls back to software on other platforms.
///
/// @param state   Current AES state (16 bytes)
/// @param rk      Round key (16 bytes)
[[nodiscard]] Vec128 enc_round(const Vec128& state, const Vec128& rk) noexcept;

/// Perform the final AES encryption round (no MixColumns).
[[nodiscard]] Vec128 enc_round_last(const Vec128& state, const Vec128& rk) noexcept;

/// Perform one AES decryption round.
[[nodiscard]] Vec128 dec_round(const Vec128& state, const Vec128& rk) noexcept;

/// Perform the final AES decryption round.
[[nodiscard]] Vec128 dec_round_last(const Vec128& state, const Vec128& rk) noexcept;

// ── Key Expansion ───────────────────────────────────────────

/// AES-128 key expansion using AESKEYGENASSIST instruction.
/// @param key  Source cipher key (16 bytes)
/// @param rk   Output: 11 round keys (176 bytes total)
void expand_key_128(std::span<const uint8_t, 16> key,
                    std::span<uint8_t, 176> rk) noexcept;

// ── Bulk Encryption ─────────────────────────────────────────

/// Encrypt multiple blocks using AES-NI (no bit-slicing overhead).
/// Falls back to scalar path on non-x86 architectures.
///
/// @param blocks    Array of 16-byte blocks
/// @param count     Number of blocks
/// @param round_keys 11 pre-expanded round keys
void encrypt_blocks(uint8_t* blocks, size_t count,
                    std::span<const uint8_t, 176> round_keys) noexcept;

/// Decrypt multiple blocks using AES-NI.
void decrypt_blocks(uint8_t* blocks, size_t count,
                    std::span<const uint8_t, 176> round_keys) noexcept;

} // namespace streamcipher::simd::aesni
