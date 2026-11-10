#include "streamcipher/stream/pipeline.hpp"
#include "streamcipher/stream/stream.hpp"
#include "../detail/wipe_guard.hpp"
#include "../io/output_transaction.hpp"
#include <algorithm>
#include <array>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <vector>

namespace streamcipher::pipeline {
struct FilePipeline::Impl {
    cipher::Algorithm algo;
    cipher::Mode mode;
    std::array<uint8_t, 16> key;
    std::array<uint8_t, 12> nonce;
    PipelineConfig::ProgressFn on_progress;
    bool running = false;
    ~Impl() { memory::secure_zero(key); memory::secure_zero(nonce); }

    uint64_t run(const std::filesystem::path& input, const std::filesystem::path& output,
                 const PipelineConfig& config, bool encrypt) {
        if (running) throw std::logic_error("Reentrant file operation");
        struct RunGuard {
            bool& flag;
            explicit RunGuard(bool& value) : flag(value) { flag = true; }
            ~RunGuard() { flag = false; }
        } guard(running);
        // Snapshot before invoking user code; replacing a callback cannot invalidate it.
        const PipelineConfig settings = config;
        const auto progress = settings.on_progress ? settings.on_progress : on_progress;
        if (settings.parallel || settings.threads != 0)
            throw std::invalid_argument("Parallel file processing is not implemented");
        const size_t chunk_size = settings.chunk_size ? settings.chunk_size : DEFAULT_CHUNK_SIZE;
        if (chunk_size > static_cast<uintmax_t>((std::numeric_limits<std::streamsize>::max)()))
            throw std::invalid_argument("Chunk size exceeds stream limits");
        const auto source = std::filesystem::absolute(input);
        const auto destination = std::filesystem::absolute(output);
        if (!std::filesystem::is_regular_file(source))
            throw std::runtime_error("Input is not a regular file");
        if (std::filesystem::exists(destination) && std::filesystem::equivalent(source, destination))
            throw std::invalid_argument("Input and output refer to the same file");
        if (std::filesystem::is_symlink(std::filesystem::symlink_status(destination)))
            throw std::invalid_argument("Output symlinks are not supported");
        if (std::filesystem::exists(destination) && !std::filesystem::is_regular_file(destination))
            throw std::invalid_argument("Output is not a regular file");
        auto proc = stream::StreamProcessor::create(algo, mode, key, nonce, encrypt);
        const uint64_t size = std::filesystem::file_size(source);
        const auto tag_size = cipher::mode_spec(mode).tag_size;
        const auto payload = encrypt ? size : cipher::decrypted_size(mode, size);
        const auto result_size = encrypt ? cipher::encrypted_size(mode, payload) : payload;
        std::ifstream in(source, std::ios::binary);
        if (!in) throw std::runtime_error("Cannot open input file");
        std::vector<uint8_t> buffer(static_cast<size_t>((std::min)(uint64_t(chunk_size), (std::max)(uint64_t{1}, payload))));
        detail::WipeGuard wipe(buffer.data(), buffer.size());
        detail::OutputTransaction staged(destination);
        uint64_t done = 0;
        while (done < payload) {
            const auto count = static_cast<size_t>((std::min)(uint64_t(buffer.size()), payload - done));
            in.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(count));
            if (!in || static_cast<size_t>(in.gcount()) != count)
                throw std::runtime_error("Input read failed or file was truncated");
            auto chunk = std::span<uint8_t>(buffer.data(), count);
            proc->process(chunk);
            staged.write(chunk);
            done += count;
            if (progress) progress(done, payload);
        }
        proc->finish();
        if (!encrypt && tag_size) {
            std::array<uint8_t, 16> expected{};
            in.read(reinterpret_cast<char*>(expected.data()), expected.size());
            if (!in || !proc->verify_tag(expected)) throw cipher::AuthenticationError();
        }
        if (in.peek() != std::char_traits<char>::eof() || in.bad())
            throw std::runtime_error("Input changed during processing or read failed");
        if (encrypt && tag_size) {
            const auto tag = proc->tag();
            staged.write(tag);
        }
        if (payload == 0 && progress) progress(0, 0);
        in.close();
        staged.publish();
        return result_size;
    }
};

FilePipeline::FilePipeline(cipher::Algorithm algo, cipher::Mode mode,
    std::span<const uint8_t, 16> key, std::span<const uint8_t, 12> nonce) : pimpl_(std::make_unique<Impl>()) {
    cipher::validate_parameters(algo, mode);
    pimpl_->algo = algo;
    pimpl_->mode = mode;
    std::copy(key.begin(), key.end(), pimpl_->key.begin());
    std::copy(nonce.begin(), nonce.end(), pimpl_->nonce.begin());
}
FilePipeline::~FilePipeline() = default;
FilePipeline::FilePipeline(FilePipeline&&) noexcept = default;
FilePipeline& FilePipeline::operator=(FilePipeline&&) noexcept = default;
uint64_t FilePipeline::encrypt_file(const std::filesystem::path& input,
    const std::filesystem::path& output, const PipelineConfig& config) {
    if (!pimpl_) throw std::logic_error("Moved-from pipeline");
    return pimpl_->run(input, output, config, true);
}
uint64_t FilePipeline::decrypt_file(const std::filesystem::path& input,
    const std::filesystem::path& output, const PipelineConfig& config) {
    if (!pimpl_) throw std::logic_error("Moved-from pipeline");
    return pimpl_->run(input, output, config, false);
}
void FilePipeline::on_progress(PipelineConfig::ProgressFn fn) {
    if (!pimpl_) throw std::logic_error("Moved-from pipeline");
    pimpl_->on_progress = std::move(fn);
}
} // namespace streamcipher::pipeline
