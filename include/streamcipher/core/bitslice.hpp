// Bit-slicing layer — SIMD-within-a-register (SWAR) for AES
//
// Rearranges B blocks so that each bit position is processed as a machine
// word. Boolean circuits replace lookup tables, giving constant-time
// execution and resistance to cache-timing attacks.
//
// Representation:
//   For SLICE_WIDTH blocks (each 16 bytes = 128 bits):
//     block[0..B-1][0..15] = 16 bytes per block
//   Bit-sliced: 128 words, word[i] = bits i of all B blocks packed together
//
// Reference: Käsper & Schwabe, "Faster and Timing-Attack Resistant AES-GCM",
//            CHES 2009.

#pragma once

#include <cstdint>
#include <cstddef>
#include <span>
#include <array>

namespace streamcipher::bitslice {

// ── Configuration ───────────────────────────────────────────

constexpr size_t BLOCK_BYTES  = 16;   // 128 bits
constexpr size_t BLOCK_BITS   = 128;
#ifdef STREAMCIPHER_SIMD
constexpr size_t SLICE_WIDTH  = 8;    // AVX2: 8 blocks in parallel
#else
constexpr size_t SLICE_WIDTH  = 8;    // Scalar: 8 blocks × 8 bits = uint64_t worth
#endif

constexpr size_t SLICE_BYTES  = SLICE_WIDTH * BLOCK_BYTES;  // Total bytes for one slice

/// A bit-slice word: one bit from each of SLICE_WIDTH blocks.
/// Always uint8_t for ABI stability; SIMD widening happens internally.
using SliceWord = uint8_t;

/// Bit-sliced AES state: 128 SliceWords, each holding one bit from all blocks.
struct alignas(64) BitSliceState {
    SliceWord bits[BLOCK_BITS];
};

// ── Conversion ──────────────────────────────────────────────

/// Pack SLICE_WIDTH byte-blocks into bit-sliced representation.
/// src: SLICE_WIDTH * 16 bytes, laid out as block[0][0..15], block[1][0..15], ...
[[nodiscard]] BitSliceState pack(std::span<const uint8_t, SLICE_BYTES> src) noexcept;

/// Unpack bit-sliced representation back to byte-blocks.
void unpack(const BitSliceState& state,
            std::span<uint8_t, SLICE_BYTES> dst) noexcept;

// ── Boolean Operations ──────────────────────────────────────

[[nodiscard]] BitSliceState xor_state(const BitSliceState& a, const BitSliceState& b) noexcept;
[[nodiscard]] BitSliceState and_state(const BitSliceState& a, const BitSliceState& b) noexcept;
[[nodiscard]] BitSliceState not_state(const BitSliceState& a) noexcept;
[[nodiscard]] BitSliceState or_state(const BitSliceState& a, const BitSliceState& b) noexcept;

// ── Bit-sliced AES Round Operations ─────────────────────────

/// SubBytes: apply the AES S-box to all 16 bytes of all SLICE_WIDTH blocks.
/// Uses a Boolean circuit — no lookup tables, constant-time.
void sub_bytes(BitSliceState& state) noexcept;

/// Inverse SubBytes.
void inv_sub_bytes(BitSliceState& state) noexcept;

/// ShiftRows: row-wise rotation of bytes.
/// Row 0: unchanged. Row 1: left 1. Row 2: left 2. Row 3: left 3.
void shift_rows(BitSliceState& state) noexcept;

/// Inverse ShiftRows.
void inv_shift_rows(BitSliceState& state) noexcept;

/// MixColumns: column-wise GF(2^8) matrix multiplication.
/// Each column (4 bytes) multiplied by:
///   [2 3 1 1]
///   [1 2 3 1]
///   [1 1 2 3]
///   [3 1 1 2]
void mix_columns(BitSliceState& state) noexcept;

/// Inverse MixColumns.
void inv_mix_columns(BitSliceState& state) noexcept;

/// AddRoundKey: XOR state with a round key (byte-oriented, not bit-sliced).
/// key: 16 bytes (one round key), applied to all SLICE_WIDTH blocks.
void add_round_key(BitSliceState& state,
                   std::span<const uint8_t, BLOCK_BYTES> key) noexcept;

// ── Full AES in Bit-Sliced Form ─────────────────────────────

/// Encrypt SLICE_WIDTH blocks using the bit-sliced path.
/// blocks: SLICE_WIDTH * 16 bytes (modified in-place).
/// round_keys: 11 round keys of 16 bytes each.
void encrypt_blocks(uint8_t* blocks,
                    std::span<const std::array<uint8_t, BLOCK_BYTES>, 11> round_keys) noexcept;

/// Decrypt SLICE_WIDTH blocks.
void decrypt_blocks(uint8_t* blocks,
                    std::span<const std::array<uint8_t, BLOCK_BYTES>, 11> round_keys) noexcept;

} // namespace streamcipher::bitslice
