// AES-128 implementation — pure C++20, no external dependencies
//
// Supports both scalar and bit-sliced execution paths.
// When AES-NI is available at runtime, delegates to simd::aesni.

#pragma once

#include <cstdint>
#include <cstddef>
#include <span>
#include <array>

namespace streamcipher::aes {

// ── Constants ───────────────────────────────────────────────

constexpr size_t BLOCK_SIZE  = 16;   // 128 bits
constexpr size_t KEY_SIZE    = 16;   // AES-128
constexpr size_t ROUNDS      = 10;   // AES-128 rounds
constexpr size_t ROUND_KEYS  = ROUNDS + 1;  // 11 round keys

// ── Key Schedule ────────────────────────────────────────────

/// Expanded key schedule: 11 round keys of 16 bytes each.
using RoundKeys = std::array<std::array<uint8_t, BLOCK_SIZE>, ROUND_KEYS>;

/// Derive round keys from a 128-bit cipher key.
[[nodiscard]] RoundKeys expand_key(std::span<const uint8_t, KEY_SIZE> key) noexcept;

// ── Core Cipher ─────────────────────────────────────────────

/// Encrypt a single 128-bit block (scalar path).
/// @param block      16-byte plaintext (modified in-place to ciphertext)
/// @param round_keys Expanded key schedule
void encrypt_block(std::span<uint8_t, BLOCK_SIZE> block,
                   const RoundKeys& round_keys) noexcept;

/// Decrypt a single 128-bit block (scalar path).
void decrypt_block(std::span<uint8_t, BLOCK_SIZE> block,
                   const RoundKeys& round_keys) noexcept;

// ── ECB Mode (single block) ─────────────────────────────────

/// Encrypt one block in ECB mode (wrapper with key expansion).
void encrypt_ecb(std::span<uint8_t, BLOCK_SIZE> block,
                 std::span<const uint8_t, KEY_SIZE> key) noexcept;

/// Decrypt one block in ECB mode.
void decrypt_ecb(std::span<uint8_t, BLOCK_SIZE> block,
                 std::span<const uint8_t, KEY_SIZE> key) noexcept;

// ── Bit-sliced batch ────────────────────────────────────────

/// Encrypt using bit-sliced path (scalar SIMD-within-a-register fallback).
/// @param blocks    Pointer to N * 16 bytes
/// @param count     Number of blocks (must be multiple of bitslice::SLICE_WIDTH)
/// @param key       16-byte key
void encrypt_bitsliced(uint8_t* blocks, size_t count,
                       std::span<const uint8_t, KEY_SIZE> key) noexcept;

// ── Hardware-accelerated ────────────────────────────────────

/// Encrypt using AES-NI if available, scalar fallback otherwise.
void encrypt_fast(uint8_t* blocks, size_t count,
                  std::span<const uint8_t, KEY_SIZE> key) noexcept;

/// Returns true if AES-NI is available at runtime.
[[nodiscard]] bool has_aesni() noexcept;

} // namespace streamcipher::aes
