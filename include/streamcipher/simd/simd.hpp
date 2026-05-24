// SIMD abstraction layer — architecture-neutral vector operations
//
// Provides a unified interface over x86 SSE/AVX and ARM NEON intrinsics.
// The compiler selects the active backend based on STREAMCIPHER_SIMD compile flag.

#pragma once

#include <cstdint>
#include <cstddef>
#include <span>

namespace streamcipher::simd {

// ── Vector Types ────────────────────────────────────────────

/// 128-bit vector (SSE4.1 / NEON)
struct alignas(16) Vec128 {
    uint8_t data[16];
};

/// 256-bit vector (AVX2)
#ifdef STREAMCIPHER_SIMD
struct alignas(32) Vec256 {
    uint8_t data[32];
};
#endif

// ── Core Operations ─────────────────────────────────────────

/// Bitwise XOR of two 128-bit vectors.
[[nodiscard]] Vec128 xor128(const Vec128& a, const Vec128& b) noexcept;

/// Galois Field multiplication (AES MixColumns helper) on 128-bit vector.
/// Performs GF multiplication lane-wise on 16 bytes.
[[nodiscard]] Vec128 gf_mul128(const Vec128& a, const Vec128& b) noexcept;

/// Shift bytes left within a 128-bit vector (used in AES ShiftRows).
[[nodiscard]] Vec128 shift_bytes_left(const Vec128& a, unsigned shift) noexcept;

/// Load 16 bytes from unaligned memory.
[[nodiscard]] Vec128 load128(const uint8_t* ptr) noexcept;

/// Store 16 bytes to unaligned memory.
void store128(uint8_t* ptr, const Vec128& v) noexcept;

// ── Batch Operations (256-bit AVX2) ─────────────────────────

#ifdef STREAMCIPHER_SIMD
/// XOR two 256-bit vectors.
[[nodiscard]] Vec256 xor256(const Vec256& a, const Vec256& b) noexcept;

/// Load 32 bytes from unaligned memory.
[[nodiscard]] Vec256 load256(const uint8_t* ptr) noexcept;

/// Store 32 bytes to unaligned memory.
void store256(uint8_t* ptr, const Vec256& v) noexcept;

/// GF(2^8) multiplication on 32 bytes in parallel.
[[nodiscard]] Vec256 gf_mul256(const Vec256& a, const Vec256& b) noexcept;
#endif

// ── CPU Feature Detection ───────────────────────────────────

/// Returns true if SSE4.1 is supported at runtime.
[[nodiscard]] bool has_sse41() noexcept;

/// Returns true if AVX2 is supported at runtime.
[[nodiscard]] bool has_avx2() noexcept;

/// Returns true if AES-NI is supported at runtime.
[[nodiscard]] bool has_aesni() noexcept;

} // namespace streamcipher::simd
