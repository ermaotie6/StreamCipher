#include "streamcipher/stream/stream.hpp"
#include "../detail/authentication.hpp"
#include "../detail/wipe_guard.hpp"
#include <cstring>
#include <stdexcept>
#include <vector>

namespace streamcipher::stream {
namespace {
class CipherStreamProcessor final : public StreamProcessor {
public:
    explicit CipherStreamProcessor(std::unique_ptr<cipher::CipherCtx> ctx) : ctx_(std::move(ctx)) {}
    void process(std::span<uint8_t> data) override {
        ctx_->update(data, data);
        processed_ += data.size();
    }
    void finish() override { ctx_->finalize(); }
    std::span<const uint8_t> tag() const override { return ctx_->tag(); }
    uint64_t bytes_processed() const noexcept override { return processed_; }
private:
    std::unique_ptr<cipher::CipherCtx> ctx_;
    uint64_t processed_ = 0;
};
}

bool StreamProcessor::verify_tag(std::span<const uint8_t> expected) const {
    return detail::verify_tag(tag(), expected);
}

std::unique_ptr<StreamProcessor> StreamProcessor::create(
    cipher::Algorithm algo, cipher::Mode mode, std::span<const uint8_t, 16> key,
    std::span<const uint8_t, 12> nonce, bool encrypt) {
    return std::make_unique<CipherStreamProcessor>(cipher::create(algo, mode, key, nonce, encrypt));
}

size_t encrypt_one_shot(cipher::Algorithm algo, cipher::Mode mode,
    std::span<const uint8_t> plaintext, std::span<uint8_t> ciphertext,
    std::span<const uint8_t, 16> key, std::span<const uint8_t, 12> nonce) {
    auto proc = StreamProcessor::create(algo, mode, key, nonce, true);
    const auto required = cipher::encrypted_size(mode, plaintext.size());
    const size_t tag_size = cipher::mode_spec(mode).tag_size;
    if (ciphertext.size() < plaintext.size() || ciphertext.size() - plaintext.size() < tag_size)
        throw std::invalid_argument("Output buffer too small");
    if (!plaintext.empty()) std::memmove(ciphertext.data(), plaintext.data(), plaintext.size());
    proc->process(ciphertext.first(plaintext.size()));
    proc->finish();
    if (tag_size) std::memcpy(ciphertext.data() + plaintext.size(), proc->tag().data(), tag_size);
    return static_cast<size_t>(required);
}

size_t decrypt_one_shot(cipher::Algorithm algo, cipher::Mode mode,
    std::span<const uint8_t> ciphertext, std::span<uint8_t> plaintext,
    std::span<const uint8_t, 16> key, std::span<const uint8_t, 12> nonce) {
    auto proc = StreamProcessor::create(algo, mode, key, nonce, false);
    const size_t tag_size = cipher::mode_spec(mode).tag_size;
    const auto size = static_cast<size_t>(cipher::decrypted_size(mode, ciphertext.size()));
    if (plaintext.size() < size) throw std::invalid_argument("Output buffer too small");
    if (tag_size) {
        // Do not expose unauthenticated plaintext, including with aliased buffers.
        std::vector<uint8_t> staged(ciphertext.begin(), ciphertext.begin() + size);
        detail::WipeGuard wipe(staged.data(), staged.size());
        proc->process(staged);
        proc->finish();
        if (!proc->verify_tag(ciphertext.last(tag_size)))
            throw cipher::AuthenticationError();
        if (size) std::memmove(plaintext.data(), staged.data(), size);
    } else {
        if (size) std::memmove(plaintext.data(), ciphertext.data(), size);
        proc->process(plaintext.first(size));
        proc->finish();
    }
    return size;
}
} // namespace streamcipher::stream
