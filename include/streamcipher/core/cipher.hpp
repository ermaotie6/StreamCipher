// Cipher abstraction — symmetric cipher interface
//
// Provides a uniform interface over all supported ciphers (AES-128, etc.)
// and block cipher modes (ECB, CTR, GCM).

#pragma once

#include "streamcipher/core/aes.hpp"
#include <cstdint>
#include <cstddef>
#include <span>
#include <memory>

namespace streamcipher::cipher {

// ── Cipher Algorithm ────────────────────────────────────────

enum class Algorithm : uint8_t {
    AES_128 = 0,
    // Future: AES_256, SM4, etc.
};

// ── Cipher Mode ─────────────────────────────────────────────

enum class Mode : uint8_t {
    ECB = 0,     // Electronic Codebook (mainly for testing)
    CTR = 1,     // Counter mode (stream cipher)
    GCM = 2,     // Galois/Counter Mode (authenticated encryption)
};

// ── Cipher Context ──────────────────────────────────────────

/// Opaque cipher context holding key material and state.
/// Created via factory functions; use RAII for automatic cleanup.
class CipherCtx {
public:
    CipherCtx() = default;
    virtual ~CipherCtx() = default;

    // Non-copyable, movable
    CipherCtx(const CipherCtx&) = delete;
    CipherCtx& operator=(const CipherCtx&) = delete;
    CipherCtx(CipherCtx&&) noexcept = default;
    CipherCtx& operator=(CipherCtx&&) noexcept = default;

    /// Process a single call (one-shot for small data; streaming calls for large).
    /// @param input  Plaintext or ciphertext
    /// @param output Buffer for output (same size as input)
    virtual void update(std::span<const uint8_t> input,
                        std::span<uint8_t> output) = 0;

    /// Finalize the operation (flushes buffers, appends authentication tag for GCM).
    virtual void finalize() = 0;

    /// Get the authentication tag (GCM only, 16 bytes).
    virtual std::span<const uint8_t> tag() const = 0;

    [[nodiscard]] Algorithm algorithm() const noexcept { return algo_; }
    [[nodiscard]] Mode      mode()      const noexcept { return mode_; }

protected:
    Algorithm algo_;
    Mode      mode_;
};

// ── Factory ─────────────────────────────────────────────────

/// Create a cipher context for the given algorithm, mode, key, and IV/nonce.
[[nodiscard]] std::unique_ptr<CipherCtx> create(
    Algorithm algo,
    Mode      mode,
    std::span<const uint8_t, 16> key,
    std::span<const uint8_t, 12> nonce  // 96-bit nonce for CTR/GCM
);

} // namespace streamcipher::cipher
