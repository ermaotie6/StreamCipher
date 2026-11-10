// In-place streaming and authenticated one-shot operations
//
// Core design: operates directly on user-provided buffers via std::span.
// StreamProcessor uses fixed context state; authenticated one-shot decryption stages payload.

#pragma once

#include "streamcipher/core/cipher.hpp"
#include <cstdint>
#include <cstddef>
#include <span>
#include <memory>

namespace streamcipher::stream {

// ── Stream Processor ────────────────────────────────────────

/// High-level streaming encryptor/decryptor.
///
/// Usage:
///   auto enc = StreamProcessor::create(cipher::Algorithm::AES_128,
///                                      cipher::Mode::CTR, key, nonce, true);
///   while (auto chunk = read_next()) {
///       enc->process(chunk);  // chunk modified in-place
///   }
///   enc->finish();
class StreamProcessor {
public:
    StreamProcessor() = default;
    virtual ~StreamProcessor() = default;
    StreamProcessor(const StreamProcessor&) = delete;
    StreamProcessor& operator=(const StreamProcessor&) = delete;

    /// Process a chunk of data in-place.
    /// For CTR mode, encrypt and decrypt are identical operations.
    /// @param data  Input/output buffer (modified in-place)
    virtual void process(std::span<uint8_t> data) = 0;

    /// Signal end-of-stream; flush any internal buffer.
    /// For GCM mode, computes the tag. Decryptors must then call verify_tag().
    virtual void finish() = 0;

    /// For authenticated modes (GCM): retrieve the computed tag.
    [[nodiscard]] virtual std::span<const uint8_t> tag() const = 0;

    /// Verify a full GCM tag after finish(). Do not use decrypted chunks until
    /// this succeeds; use one-shot/file APIs to stage output automatically.
    [[nodiscard]] bool verify_tag(std::span<const uint8_t> expected) const;

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

    static std::unique_ptr<StreamProcessor> create(
        cipher::Algorithm algo, cipher::Mode mode,
        std::span<const uint8_t, cipher::KEY_SIZE> key,
        std::span<const uint8_t, cipher::NONCE_SIZE> nonce, cipher::Direction direction) {
        if (direction != cipher::Direction::Encrypt && direction != cipher::Direction::Decrypt)
            throw std::invalid_argument("Unsupported cipher direction");
        return create(algo, mode, key, nonce, direction == cipher::Direction::Encrypt);
    }
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

/// Decrypt a buffer. GCM verifies the appended tag before changing output.
/// Throws on authentication failure, invalid parameters or insufficient capacity.
size_t decrypt_one_shot(cipher::Algorithm algo,
                        cipher::Mode      mode,
                        std::span<const uint8_t> ciphertext,
                        std::span<uint8_t>       plaintext,
                        std::span<const uint8_t, 16> key,
                        std::span<const uint8_t, 12> nonce);

} // namespace streamcipher::stream
