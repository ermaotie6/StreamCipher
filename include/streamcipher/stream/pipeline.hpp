// Data pipeline for file-level encryption/decryption
//
// Handles buffered I/O, padding, and multi-stage processing
// with configurable buffer sizes and thread parallelism.

#pragma once

#include "streamcipher/stream/stream.hpp"
#include <cstdint>
#include <cstddef>
#include <span>
#include <filesystem>
#include <string>
#include <memory>

namespace streamcipher::pipeline {

// ── Configuration ───────────────────────────────────────────

struct PipelineConfig {
    /// Chunk size for file I/O (default: 1 MiB)
    size_t chunk_size = 1 << 20;

    /// If true, use multiple threads for independent chunks (CTR mode only).
    bool parallel = false;

    /// Number of threads for parallel processing (0 = auto-detect).
    unsigned threads = 0;

    /// Callback for progress reporting: (bytes_processed, total_bytes)
    using ProgressFn = std::function<void(uint64_t, uint64_t)>;
    ProgressFn on_progress;
};

// ── Pipeline ────────────────────────────────────────────────

/// High-level file encryption/decryption pipeline.
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

    /// Encrypt a file: plaintext → ciphertext.
    /// @return Number of bytes written (includes tag for GCM mode).
    [[nodiscard]] uint64_t encrypt_file(const std::filesystem::path& input,
                                        const std::filesystem::path& output,
                                        const PipelineConfig& config = {});

    /// Decrypt a file: ciphertext → plaintext.
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
