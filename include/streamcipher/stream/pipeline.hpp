// Data pipeline for file-level encryption/decryption
//
// Bounded-memory sequential I/O with authenticated transactional publication.

#pragma once

#include "streamcipher/core/parameters.hpp"
#include <cstdint>
#include <cstddef>
#include <span>
#include <filesystem>
#include <functional>
#include <memory>

namespace streamcipher::pipeline {

// ── Configuration ───────────────────────────────────────────

inline constexpr size_t DEFAULT_CHUNK_SIZE = 1 << 20;

struct PipelineConfig {
    /// Chunk size for file I/O (default: 1 MiB)
    size_t chunk_size = DEFAULT_CHUNK_SIZE;

    /// Reserved; requesting parallel processing currently throws invalid_argument.
    bool parallel = false;

    /// Reserved; must be zero until parallel processing is implemented.
    unsigned threads = 0;

    /// Payload progress, not publication success. Exceptions cancel the operation.
    /// Configuration and callback are copied at operation start.
    using ProgressFn = std::function<void(uint64_t, uint64_t)>;
    ProgressFn on_progress;
};

// ── Pipeline ────────────────────────────────────────────────

/// High-level file encryption/decryption pipeline.
/// Each call creates fresh cipher state. Caller manages nonce uniqueness.
/// An object is not safe for concurrent mutation; independent objects are independent.
/// Do not destroy or move this object from its own progress callback.
class FilePipeline {
public:
    /// @param algo  Cipher algorithm
    /// @param mode  Cipher mode of operation
    /// @param key   16-byte key
    /// @param nonce 12-byte nonce (for CTR/GCM)
    FilePipeline(cipher::Algorithm algo,
                 cipher::Mode      mode,
                 std::span<const uint8_t, 16> key,
                 std::span<const uint8_t, 12> nonce);

    ~FilePipeline();

    // Non-copyable, movable
    FilePipeline(const FilePipeline&) = delete;
    FilePipeline& operator=(const FilePipeline&) = delete;
    FilePipeline(FilePipeline&&) noexcept;
    FilePipeline& operator=(FilePipeline&&) noexcept;

    /// Encrypt a file: plaintext → ciphertext. Throws on I/O/parameter errors.
    /// Output is replaced only after success; input/output aliases are rejected.
    /// @return Number of bytes written (includes tag for GCM mode).
    [[nodiscard]] uint64_t encrypt_file(const std::filesystem::path& input,
                                        const std::filesystem::path& output,
                                        const PipelineConfig& config = {});

    /// Decrypt a file; GCM authentication must succeed before publishing output.
    /// Throws on I/O/parameter/authentication errors. Zero bytes is valid success.
    [[nodiscard]] uint64_t decrypt_file(const std::filesystem::path& input,
                                        const std::filesystem::path& output,
                                        const PipelineConfig& config = {});

    /// Set progress callback.
    void on_progress(PipelineConfig::ProgressFn fn);

private:
    struct Impl;
    std::unique_ptr<Impl> pimpl_;
};

} // namespace streamcipher::pipeline
