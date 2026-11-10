// Cipher abstraction — symmetric cipher interface
//
// Provides a uniform interface for AES-128 CTR/GCM messages.
// The retained ECB enum is not supported by this streaming factory.

#pragma once

#include "streamcipher/core/parameters.hpp"
#include <cstdint>
#include <cstddef>
#include <span>
#include <memory>

namespace streamcipher::cipher {

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

    /// Finalize once; repeated calls are harmless. Updates afterwards throw.
    virtual void finalize() = 0;

    /// Get the authentication tag (GCM only, 16 bytes after finalize()).
    virtual std::span<const uint8_t> tag() const = 0;

    /// Compare all 16 bytes after finalize(). Decrypted output is untrusted
    /// until this returns true.
    [[nodiscard]] bool verify_tag(std::span<const uint8_t> expected) const;

    [[nodiscard]] Algorithm algorithm() const noexcept { return algo_; }
    [[nodiscard]] Mode      mode()      const noexcept { return mode_; }

protected:
    Algorithm algo_ = Algorithm::AES_128;
    Mode      mode_ = Mode::CTR;
};

// ── Factory ─────────────────────────────────────────────────

/// Create a cipher context for the given algorithm, mode, key, and IV/nonce.
[[nodiscard]] std::unique_ptr<CipherCtx> create(
    Algorithm algo,
    Mode      mode,
    std::span<const uint8_t, 16> key,
    std::span<const uint8_t, 12> nonce, // 96-bit nonce for CTR/GCM
    bool encrypt = true
);

// Typed direction overload; bool entry point remains source-compatible.
[[nodiscard]] inline std::unique_ptr<CipherCtx> create(
    Algorithm algo, Mode mode, std::span<const uint8_t, KEY_SIZE> key,
    std::span<const uint8_t, NONCE_SIZE> nonce, Direction direction) {
    if (direction != Direction::Encrypt && direction != Direction::Decrypt)
        throw std::invalid_argument("Unsupported cipher direction");
    return create(algo, mode, key, nonce, direction == Direction::Encrypt);
}
} // namespace streamcipher::cipher
