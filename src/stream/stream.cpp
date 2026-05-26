// stream.cpp — 流式加解密，支持分块处理
//
// CTR 的 StreamProcessor 核心思路：不管数据怎么分块，字节位置 N
// 永远用 keystream[N mod 16]（来自 counter[N/16] 的加密结果）。
// 所以 counter 从绝对字节位置算，不依赖"上次处理到哪了"——这是踩过坑之后改的。
//
// GCM 就简单了：直接套 cipher::CipherCtx（GCM 模式），
// 加一层 thread_local buffer 做中转（因为 cipher::update 不支持原地）。

#include "streamcipher/stream/stream.hpp"
#include "streamcipher/core/aes.hpp"
#include <cstring>
#include <vector>
#include <array>

namespace streamcipher::stream {

namespace {

// ---- CTR StreamProcessor ----
// 这个实现的关键：counter 从 absolute byte position 算，不是增量。
// 否则跨 process() 调用的分块边界会导致 counter 错位（血的教训）。

class CtrStreamProcessor : public StreamProcessor {
public:
    CtrStreamProcessor(cipher::Algorithm algo,
                       std::span<const uint8_t, 16> key,
                       std::span<const uint8_t, 12> nonce) {
        std::memcpy(key_, key.data(), 16);
        std::memcpy(counter_, nonce.data(), 12);
        counter_[12] = counter_[13] = counter_[14] = counter_[15] = 0;
        (void)algo;
        round_keys_ = aes::expand_key(std::span<const uint8_t, 16>(key_, 16));
    }

    void process(std::span<uint8_t> data) override {
        std::array<uint8_t, 16> keystream;
        size_t offset = 0;

        while (offset < data.size()) {
            uint64_t abs_pos = bytes_processed_ + offset;
            size_t block_num = abs_pos / 16;
            size_t byte_in_block = abs_pos % 16;

            set_counter(block_num);

            std::memcpy(keystream.data(), counter_, 16);
            aes::encrypt_block(std::span<uint8_t, 16>(keystream), round_keys_);

            size_t chunk = std::min(size_t(16) - byte_in_block, data.size() - offset);
            for (size_t i = 0; i < chunk; ++i)
                data[offset + i] ^= keystream[byte_in_block + i];
            offset += chunk;
        }
        bytes_processed_ += data.size();
    }

    void finish() override {}
    std::span<const uint8_t> tag() const override { return {}; }
    uint64_t bytes_processed() const noexcept override { return bytes_processed_; }

private:
    void set_counter(uint64_t block_num) noexcept {
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

// ---- GCM StreamProcessor ----
// 这里只是对 cipher::GcmCipherCtx 包一层，因为 GCM 的 update 不支持原地操作
// 所以用 thread_local 的临时 buffer 中转一下。有点糙但能用。

class GcmStreamProcessor : public StreamProcessor {
public:
    GcmStreamProcessor(cipher::Algorithm algo,
                       std::span<const uint8_t, 16> key,
                       std::span<const uint8_t, 12> nonce,
                       bool encrypt)
        : encrypt_(encrypt) {
        std::memcpy(key_, key.data(), 16);
        std::memcpy(nonce_, nonce.data(), 12);
        (void)algo;
        ctx_ = cipher::create(cipher::Algorithm::AES_128, cipher::Mode::GCM,
                              std::span<const uint8_t, 16>(key_),
                              std::span<const uint8_t, 12>(nonce_));
    }

    void process(std::span<uint8_t> data) override {
        if (!ctx_) return;
        thread_local std::vector<uint8_t> tmp;   // 省的每次重新分配
        tmp.resize(data.size());
        ctx_->update(data, tmp);
        std::memcpy(data.data(), tmp.data(), data.size());
        bytes_processed_ += data.size();
    }

    void finish() override { if (ctx_) ctx_->finalize(); }

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

// ---- 工厂 + 便捷函数 ----

std::unique_ptr<StreamProcessor> StreamProcessor::create(
    cipher::Algorithm algo, cipher::Mode mode,
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

size_t encrypt_one_shot(cipher::Algorithm algo, cipher::Mode mode,
                        std::span<const uint8_t> plaintext,
                        std::span<uint8_t> ciphertext,
                        std::span<const uint8_t, 16> key,
                        std::span<const uint8_t, 12> nonce)
{
    auto proc = StreamProcessor::create(algo, mode, key, nonce, true);
    if (!proc) return 0;

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

size_t decrypt_one_shot(cipher::Algorithm algo, cipher::Mode mode,
                        std::span<const uint8_t> ciphertext,
                        std::span<uint8_t> plaintext,
                        std::span<const uint8_t, 16> key,
                        std::span<const uint8_t, 12> nonce)
{
    auto proc = StreamProcessor::create(algo, mode, key, nonce, false);
    if (!proc) return 0;

    // GCM: 最后 16 字节是 tag，不算在 payload 里
    size_t payload_size = (mode == cipher::Mode::GCM && ciphertext.size() >= 16)
                          ? ciphertext.size() - 16 : ciphertext.size();

    std::memcpy(plaintext.data(), ciphertext.data(), payload_size);
    proc->process(plaintext.first(payload_size));
    proc->finish();
    return payload_size;
}

} // namespace streamcipher::stream
