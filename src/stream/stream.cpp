// Streaming encryption/decryption framework
#include "streamcipher/stream/stream.hpp"
#include "streamcipher/core/aes.hpp"
#include <cstring>
#include <vector>
#include <array>

namespace streamcipher::stream {

// ═══════════════════════════════════════════════════════════════
//  CTR Stream Processor — truly in-place
// ═══════════════════════════════════════════════════════════════

namespace {

class CtrStreamProcessor : public StreamProcessor {
public:
    CtrStreamProcessor(cipher::Algorithm algo,
                       std::span<const uint8_t, 16> key,
                       std::span<const uint8_t, 12> nonce)
    {
        std::memcpy(key_, key.data(), 16);
        std::memcpy(counter_, nonce.data(), 12);
        counter_[12] = counter_[13] = counter_[14] = counter_[15] = 0;
        (void)algo; // currently only AES-128 supported
        round_keys_ = aes::expand_key(std::span<const uint8_t, 16>(key_, 16));
    }

    void process(std::span<uint8_t> data) override {
        std::array<uint8_t, 16> keystream;
        size_t offset = 0;

        while (offset < data.size()) {
            // Determine absolute byte position
            uint64_t abs_pos = bytes_processed_ + offset;
            size_t block_num = abs_pos / 16;
            size_t byte_in_block = abs_pos % 16;

            // Set counter to the correct block number
            set_counter(block_num);

            // Generate keystream for this block
            std::memcpy(keystream.data(), counter_, 16);
            aes::encrypt_block(std::span<uint8_t, 16>(keystream), round_keys_);

            // XOR with data, starting at byte_in_block within the keystream
            size_t chunk = std::min(size_t(16) - byte_in_block, data.size() - offset);
            for (size_t i = 0; i < chunk; ++i) {
                data[offset + i] ^= keystream[byte_in_block + i];
            }
            offset += chunk;
        }
        bytes_processed_ += data.size();
    }

    void finish() override {}

    std::span<const uint8_t> tag() const override { return {}; }

    uint64_t bytes_processed() const noexcept override { return bytes_processed_; }

private:
    void set_counter(uint64_t block_num) noexcept {
        // counter_[12..15] is the 32-bit big-endian block counter
        uint32_t ctr = static_cast<uint32_t>(block_num);
        counter_[12] = (ctr >> 24) & 0xFF;
        counter_[13] = (ctr >> 16) & 0xFF;
        counter_[14] = (ctr >> 8) & 0xFF;
        counter_[15] = ctr & 0xFF;
    }

    alignas(64) uint8_t key_[16];
    alignas(64) uint8_t counter_[16];
    aes::RoundKeys round_keys_;
    uint64_t bytes_processed_ = 0;
};

// ═══════════════════════════════════════════════════════════════
//  GCM Stream Processor
// ═══════════════════════════════════════════════════════════════

class GcmStreamProcessor : public StreamProcessor {
public:
    GcmStreamProcessor(cipher::Algorithm algo,
                       std::span<const uint8_t, 16> key,
                       std::span<const uint8_t, 12> nonce,
                       bool encrypt)
        : encrypt_(encrypt)
    {
        std::memcpy(key_, key.data(), 16);
        std::memcpy(nonce_, nonce.data(), 12);
        (void)algo;
        ctx_ = cipher::create(cipher::Algorithm::AES_128, cipher::Mode::GCM,
                              std::span<const uint8_t, 16>(key_),
                              std::span<const uint8_t, 12>(nonce_));
    }

    void process(std::span<uint8_t> data) override {
        if (!ctx_) return;
        thread_local std::vector<uint8_t> tmp;
        tmp.resize(data.size());
        ctx_->update(data, tmp);
        std::memcpy(data.data(), tmp.data(), data.size());
        bytes_processed_ += data.size();
    }

    void finish() override {
        if (ctx_) ctx_->finalize();
    }

    std::span<const uint8_t> tag() const override {
        return ctx_ ? ctx_->tag() : std::span<const uint8_t>{};
    }

    uint64_t bytes_processed() const noexcept override { return bytes_processed_; }

private:
    uint8_t key_[16];
    uint8_t nonce_[12];
    bool encrypt_;
    std::unique_ptr<cipher::CipherCtx> ctx_;
    uint64_t bytes_processed_ = 0;
};

} // anonymous namespace

// ═══════════════════════════════════════════════════════════════
//  Factory
// ═══════════════════════════════════════════════════════════════

std::unique_ptr<StreamProcessor> StreamProcessor::create(
    cipher::Algorithm algo,
    cipher::Mode      mode,
    std::span<const uint8_t, 16> key,
    std::span<const uint8_t, 12> nonce,
    bool encrypt)
{
    switch (mode) {
    case cipher::Mode::CTR:
        return std::make_unique<CtrStreamProcessor>(algo, key, nonce);
    case cipher::Mode::GCM:
        return std::make_unique<GcmStreamProcessor>(algo, key, nonce, encrypt);
    default:
        return nullptr;
    }
}

// ═══════════════════════════════════════════════════════════════
//  One-Shot Convenience Functions
// ═══════════════════════════════════════════════════════════════

size_t encrypt_one_shot(cipher::Algorithm algo,
                        cipher::Mode      mode,
                        std::span<const uint8_t> plaintext,
                        std::span<uint8_t>       ciphertext,
                        std::span<const uint8_t, 16> key,
                        std::span<const uint8_t, 12> nonce)
{
    auto proc = StreamProcessor::create(algo, mode, key, nonce, true);
    if (!proc) return 0;

    // Copy to output buffer for in-place processing
    std::memcpy(ciphertext.data(), plaintext.data(), plaintext.size());
    proc->process(ciphertext.first(plaintext.size()));
    proc->finish();

    size_t total = plaintext.size();
    if (auto t = proc->tag(); !t.empty()) {
        std::memcpy(ciphertext.data() + plaintext.size(), t.data(), t.size());
        total += t.size();
    }
    return total;
}

size_t decrypt_one_shot(cipher::Algorithm algo,
                        cipher::Mode      mode,
                        std::span<const uint8_t> ciphertext,
                        std::span<uint8_t>       plaintext,
                        std::span<const uint8_t, 16> key,
                        std::span<const uint8_t, 12> nonce)
{
    auto proc = StreamProcessor::create(algo, mode, key, nonce, false);
    if (!proc) return 0;

    // For GCM, last 16 bytes are the tag
    size_t payload_size = (mode == cipher::Mode::GCM && ciphertext.size() >= 16)
                          ? ciphertext.size() - 16 : ciphertext.size();

    std::memcpy(plaintext.data(), ciphertext.data(), payload_size);
    proc->process(plaintext.first(payload_size));
    proc->finish();

    return payload_size;
}

} // namespace streamcipher::stream
