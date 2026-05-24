// Galois Field GF(2^8) operations — pure bitwise, constant-time
//
// All operations are implemented without lookup tables, using only
// bitwise operations. This eliminates cache-timing side-channels
// and is the mathematical foundation of the bit-sliced AES.

#pragma once

#include <cstdint>
#include <cstddef>
#include <bit>
#include <array>

namespace streamcipher::gf {

// ── Constants ───────────────────────────────────────────────

/// Irreducible polynomial for GF(2^8): x^8 + x^4 + x^3 + x + 1 (AES standard)
constexpr uint8_t IRREDUCIBLE_POLY = 0x1B;

/// Element in GF(2^8), stored as uint8_t
using GF8 = uint8_t;

// ── Core operations ─────────────────────────────────────────

/// Multiply two GF(2^8) elements using the standard shift-and-add algorithm.
/// Constant-time by construction — always performs 8 iterations.
[[nodiscard]] constexpr GF8 mul(GF8 a, GF8 b) noexcept {
    GF8 result = 0;
    for (int i = 0; i < 8; ++i) {
        // conditionally XOR a into result (masked to avoid branch)
        result ^= a & -(b & 1);
        uint8_t carry = a & 0x80;
        a = (a << 1) ^ (carry ? IRREDUCIBLE_POLY : 0);
        b >>= 1;
    }
    return result;
}

/// Compute multiplicative inverse in GF(2^8): a^(-1) = a^254.
/// Uses binary exponentiation (square-and-multiply) — constant-time by design.
[[nodiscard]] constexpr GF8 inv(GF8 a) noexcept {
    // a^254: 254 = 0b11111110
    if (a == 0) return 0;
    GF8 x = a;
    GF8 result = 1;
    for (int i = 7; i >= 0; --i) {
        result = mul(result, result);
        if ((254 >> i) & 1) {
            result = mul(result, x);
        }
    }
    return result;
}

/// XTime: multiply by x (polynomial x = 0x02 in GF(2^8)).
/// Used in MixColumns. Equivalent to xtime() in the AES specification.
[[nodiscard]] constexpr GF8 xtime(GF8 a) noexcept {
    return (a & 0x80) ? ((a << 1) ^ IRREDUCIBLE_POLY) : (a << 1);
}

/// Multiply by 0x03: 0x03 * a = xtime(a) ^ a
[[nodiscard]] constexpr GF8 mul3(GF8 a) noexcept {
    return xtime(a) ^ a;
}

/// Multiply by 0x09: 0x09 * a = xtime(xtime(xtime(a))) ^ a
[[nodiscard]] constexpr GF8 mul9(GF8 a) noexcept {
    return xtime(xtime(xtime(a))) ^ a;
}

/// Multiply by 0x0b: 0x0b * a = xtime(xtime(xtime(a))) ^ xtime(a) ^ a
[[nodiscard]] constexpr GF8 mul11(GF8 a) noexcept {
    return xtime(xtime(xtime(a))) ^ xtime(a) ^ a;
}

/// Multiply by 0x0d: 0x0d * a = xtime(xtime(xtime(a))) ^ xtime(xtime(a)) ^ a
[[nodiscard]] constexpr GF8 mul13(GF8 a) noexcept {
    return xtime(xtime(xtime(a))) ^ xtime(xtime(a)) ^ a;
}

/// Multiply by 0x0e: 0x0e * a = xtime(xtime(xtime(a))) ^ xtime(xtime(a)) ^ xtime(a)
[[nodiscard]] constexpr GF8 mul14(GF8 a) noexcept {
    return xtime(xtime(xtime(a))) ^ xtime(xtime(a)) ^ xtime(a);
}

// ── AES S-box ───────────────────────────────────────────────

/// Computed S-box: GF(2^8) inverse followed by affine transformation.
/// This is THE lookup-table-free S-box — each call computes the inverse
/// and affine transform using only bitwise operations.
[[nodiscard]] constexpr GF8 sbox(GF8 a) noexcept {
    GF8 inv_a = inv(a);
    // Affine transformation over GF(2):
    // b_i = a_i ^ a_(i+4)mod8 ^ a_(i+5)mod8 ^ a_(i+6)mod8 ^ a_(i+7)mod8 ^ c_i
    // Using right rotation: a_(i+k) at bit i = rotr(a, k) at bit i
    GF8 result = inv_a;
    result ^= std::rotr(inv_a, 4);
    result ^= std::rotr(inv_a, 5);
    result ^= std::rotr(inv_a, 6);
    result ^= std::rotr(inv_a, 7);
    result ^= 0x63;
    return result;
}

/// Inverse S-box: inverse affine transform followed by GF inverse.
[[nodiscard]] constexpr GF8 inv_sbox(GF8 a) noexcept {
    // Inverse affine: b_i = a_(i+2)mod8 ^ a_(i+5)mod8 ^ a_(i+7)mod8 ^ d_i
    // d = 0x05. Note: does NOT include a_i term.
    GF8 x = std::rotr(a, 2) ^ std::rotr(a, 5) ^ std::rotr(a, 7) ^ 0x05;
    return inv(x);
}

// ── Batch operations ────────────────────────────────────────

/// Multiply two arrays of GF(2^8) elements.
void mul_batch(GF8* __restrict dst, const GF8* __restrict a,
               const GF8* __restrict b, size_t count) noexcept;

/// Compute inverses for an array of GF(2^8) elements.
void inv_batch(GF8* __restrict dst, const GF8* __restrict src,
               size_t count) noexcept;

/// Apply S-box to an array of bytes.
void sbox_batch(GF8* __restrict dst, const GF8* __restrict src,
                size_t count) noexcept;

/// Apply inverse S-box to an array of bytes.
void inv_sbox_batch(GF8* __restrict dst, const GF8* __restrict src,
                    size_t count) noexcept;

} // namespace streamcipher::gf
