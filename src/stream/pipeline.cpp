// File pipeline — streaming file encryption/decryption
#include "streamcipher/stream/pipeline.hpp"
#include <fstream>
#include <vector>
#include <algorithm>

namespace streamcipher::pipeline {

struct FilePipeline::Impl {
    cipher::Algorithm algo;
    cipher::Mode      mode;
    std::array<uint8_t, 16> key;
    std::array<uint8_t, 12> nonce;
    PipelineConfig::ProgressFn on_progress;
};

FilePipeline::FilePipeline(cipher::Algorithm algo,
                           cipher::Mode      mode,
                           std::span<const uint8_t, 16> key,
                           std::span<const uint8_t, 12> nonce)
    : pimpl_(std::make_unique<Impl>())
{
    pimpl_->algo = algo;
    pimpl_->mode = mode;
    std::copy(key.begin(), key.end(), pimpl_->key.begin());
    std::copy(nonce.begin(), nonce.end(), pimpl_->nonce.begin());
}

FilePipeline::~FilePipeline() = default;
FilePipeline::FilePipeline(FilePipeline&&) noexcept = default;
FilePipeline& FilePipeline::operator=(FilePipeline&&) noexcept = default;

uint64_t FilePipeline::encrypt_file(const std::filesystem::path& input,
                                     const std::filesystem::path& output,
                                     const PipelineConfig& config) {
    std::ifstream in(input, std::ios::binary);
    if (!in) return 0;

    auto size = std::filesystem::file_size(input);

    auto proc = stream::StreamProcessor::create(
        pimpl_->algo, pimpl_->mode,
        std::span<const uint8_t, 16>(pimpl_->key),
        std::span<const uint8_t, 12>(pimpl_->nonce),
        true
    );
    if (!proc) return 0;

    // Write header: for GCM mode, we'll prepend the tag later.
    // For CTR mode, just stream raw.
    std::ofstream out(output, std::ios::binary);
    if (!out) return 0;

    // Use a 256 KiB buffer for efficient I/O
    size_t chunk_size = config.chunk_size > 0 ? config.chunk_size : (256 * 1024);
    std::vector<uint8_t> buffer(chunk_size);
    uint64_t total_processed = 0;

    while (in && total_processed < size) {
        size_t to_read = std::min(buffer.size(), static_cast<size_t>(size - total_processed));
        in.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(to_read));
        size_t bytes_read = static_cast<size_t>(in.gcount());
        if (bytes_read == 0) break;

        auto chunk = std::span<uint8_t>(buffer.data(), bytes_read);
        proc->process(chunk);
        out.write(reinterpret_cast<const char*>(chunk.data()),
                  static_cast<std::streamsize>(chunk.size()));
        total_processed += bytes_read;

        if (pimpl_->on_progress) {
            pimpl_->on_progress(total_processed, size);
        }
    }

    proc->finish();

    // For GCM, append the 16-byte authentication tag
    if (auto t = proc->tag(); !t.empty()) {
        out.write(reinterpret_cast<const char*>(t.data()),
                  static_cast<std::streamsize>(t.size()));
        total_processed += t.size();
    }

    return total_processed;
}

uint64_t FilePipeline::decrypt_file(const std::filesystem::path& input,
                                     const std::filesystem::path& output,
                                     const PipelineConfig& config) {
    std::ifstream in(input, std::ios::binary);
    if (!in) return 0;

    auto size = std::filesystem::file_size(input);
    size_t payload_size = size;

    // For GCM, the last 16 bytes are the tag — read them separately
    if (pimpl_->mode == cipher::Mode::GCM && size >= 16) {
        payload_size = size - 16;
    }

    auto proc = stream::StreamProcessor::create(
        pimpl_->algo, pimpl_->mode,
        std::span<const uint8_t, 16>(pimpl_->key),
        std::span<const uint8_t, 12>(pimpl_->nonce),
        false
    );
    if (!proc) return 0;

    std::ofstream out(output, std::ios::binary);
    if (!out) return 0;

    size_t chunk_size = config.chunk_size > 0 ? config.chunk_size : (256 * 1024);
    std::vector<uint8_t> buffer(chunk_size);
    uint64_t total_read = 0;

    while (in && total_read < payload_size) {
        size_t to_read = std::min(buffer.size(), payload_size - total_read);
        in.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(to_read));
        size_t bytes_read = static_cast<size_t>(in.gcount());
        if (bytes_read == 0) break;

        auto chunk = std::span<uint8_t>(buffer.data(), bytes_read);
        proc->process(chunk);
        out.write(reinterpret_cast<const char*>(chunk.data()),
                  static_cast<std::streamsize>(chunk.size()));
        total_read += bytes_read;

        if (pimpl_->on_progress) {
            pimpl_->on_progress(total_read, payload_size);
        }
    }

    proc->finish();
    return total_read;
}

void FilePipeline::on_progress(PipelineConfig::ProgressFn fn) {
    pimpl_->on_progress = std::move(fn);
}

} // namespace streamcipher::pipeline
