// Streaming encryption/decryption framework — zero-copy pipeline
//
// Core design: operates directly on user-provided buffers via std::span.
// No internal copying of payload data — only small fixed-size context state.

#pragma once

#include "streamcipher/core/cipher.hpp"
#include "streamcipher/memory/span_utils.hpp"
#include <cstdint>
#include <cstddef>
#include <span>
#include <memory>
#include <functional>

namespace streamcipher::stream {

// ── Stream Processor ────────────────────────────────────────

/// High-level streaming encryptor/decryptor.
///
/// Usage:
///   auto enc = StreamProcessor::create(cipher::Algorithm::AES_128,
///                                      cipher::Mode::CTR, key, nonce);
///   while (auto chunk = read_next()) {
///       enc->process(chunk);  // chunk modified in-place
///   }
///   enc->finish();
class StreamProcessor {
public:
    virtual ~StreamProcessor() = default;

    /// Process a chunk of data in-place.
    /// For CTR mode, encrypt and decrypt are identical operations.
    /// @param data  Input/output buffer (modified in-place)
    virtual void process(std::span<uint8_t> data) = 0;

    /// Signal end-of-stream; flush any internal buffer.
    /// For GCM mode, validates/emits the authentication tag.
    virtual void finish() = 0;

    /// For authenticated modes (GCM): retrieve the computed tag.
    [[nodiscard]] virtual std::span<const uint8_t> tag() const = 0;

    /// Number of bytes processed so far.
    [[nodiscard]] virtual uint64_t bytes_processed() const noexcept = 0;

    // ── Factory ──────────────────────────────────────────────

    /// Create a stream processor.
    /// @param algo    Cipher algorithm
    /// @param mode    Cipher mode of operation
    /// @param key     16-byte key
    /// @param nonce   12-byte nonce (for CTR/GCM)
    /// @param encrypt true = encryption, false = decryption
    static std::unique_ptr<StreamProcessor> create(
        cipher::Algorithm algo,
        cipher::Mode      mode,
        std::span<const uint8_t, 16> key,
        std::span<const uint8_t, 12> nonce,
        bool encrypt
    );
};

// ── Convenience Functions ───────────────────────────────────

/// Encrypt an entire buffer in one shot (small data, testing).
/// @return Number of output bytes (same as input for CTR; +16 for GCM tag)
size_t encrypt_one_shot(cipher::Algorithm algo,
                        cipher::Mode      mode,
                        std::span<const uint8_t> plaintext,
                        std::span<uint8_t>       ciphertext,
                        std::span<const uint8_t, 16> key,
                        std::span<const uint8_t, 12> nonce);

/// Decrypt an entire buffer in one shot.
size_t decrypt_one_shot(cipher::Algorithm algo,
                        cipher::Mode      mode,
                        std::span<const uint8_t> ciphertext,
                        std::span<uint8_t>       plaintext,
                        std::span<const uint8_t, 16> key,
                        std::span<const uint8_t, 12> nonce);

} // namespace streamcipher::stream
