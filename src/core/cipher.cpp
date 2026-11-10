// AES-128 CTR and GCM (96-bit nonce, no additional authenticated data).
#include "streamcipher/core/cipher.hpp"
#include "streamcipher/simd/aesni.hpp"
#include "ghash.hpp"
#include "../detail/authentication.hpp"
#include <algorithm>
#include <array>
#include <cstring>
#include <stdexcept>

namespace streamcipher::cipher {
namespace {
using detail::Block;

class AesCipherCtx final : public CipherCtx {
public:
    AesCipherCtx(Mode mode, std::span<const uint8_t, 16> key,
                 std::span<const uint8_t, 12> nonce, bool encrypt) : spec_(mode_spec(mode)), encrypt_(encrypt) {
        algo_ = Algorithm::AES_128;
        mode_ = mode;
        std::copy(nonce.begin(), nonce.end(), counter_.begin());
        simd::aesni::expand_key_128(key, round_keys_);
        if (mode_ == Mode::GCM) {
            Block h{};
            encrypt_block(h);
            hash_.set_key(h);
            memory::secure_zero(h);
            j0_ = counter_;
            j0_[15] = 1;
            encrypt_block(j0_);
        }
    }

    ~AesCipherCtx() override {
        memory::secure_zero(round_keys_);
        memory::secure_zero(counter_); memory::secure_zero(keystream_);
        memory::secure_zero(j0_); memory::secure_zero(pending_); memory::secure_zero(tag_);
    }

    void update(std::span<const uint8_t> input, std::span<uint8_t> output) override {
        if (finished_) throw std::logic_error("Cipher already finalized");
        if (output.size() < input.size()) throw std::invalid_argument("Output buffer too small");
        validate_length(mode_, processed_, input.size());
        // Exact in-place operation is supported; partial overlap is not.
        if (!input.empty() && input.data() != output.data()) {
            const auto a = reinterpret_cast<uintptr_t>(input.data());
            const auto b = reinterpret_cast<uintptr_t>(output.data());
            if ((a < b ? b - a : a - b) < input.size())
                throw std::invalid_argument("Partially overlapping cipher buffers");
        }
        for (size_t off = 0; off < input.size(); ++off) {
            const size_t pos = static_cast<size_t>(processed_ % 16);
            if (pos == 0) {
                const uint32_t counter = static_cast<uint32_t>(processed_ / 16 + spec_.initial_counter);
                for (size_t i = 0; i < 4; ++i)
                    counter_[12 + i] = static_cast<uint8_t>(counter >> (24 - i * 8));
                keystream_ = counter_;
                encrypt_block(keystream_);
            }
            const uint8_t source = input[off];
            const uint8_t result = source ^ keystream_[pos];
            output[off] = result;
            if (mode_ == Mode::GCM) {
                pending_[pos] = encrypt_ ? result : source;
                if (pos == 15) { hash_.update(pending_); pending_.fill(0); }
            }
            ++processed_;
        }
    }

    void finalize() override {
        if (finished_) return;
        if (mode_ == Mode::GCM) {
            if (processed_ % 16 != 0) hash_.update(pending_);
            Block lengths{};
            const uint64_t bits = processed_ * 8;
            for (size_t i = 0; i < 8; ++i)
                lengths[15 - i] = static_cast<uint8_t>(bits >> (i * 8));
            hash_.update(lengths);
            for (size_t i = 0; i < 16; ++i) tag_[i] = hash_.value()[i] ^ j0_[i];
        }
        finished_ = true;
    }

    std::span<const uint8_t> tag() const override {
        if (mode_ != Mode::GCM || !finished_) return {};
        return tag_;
    }

private:
    void encrypt_block(Block& block) const noexcept {
        simd::aesni::encrypt_blocks(block.data(), 1, round_keys_);
    }
    std::array<uint8_t, 176> round_keys_{};
    Block counter_{}, keystream_{}, j0_{}, pending_{}, tag_{};
    detail::GHash hash_;
    const ModeSpec spec_;
    uint64_t processed_ = 0;
    bool encrypt_;
    bool finished_ = false;
};
} // namespace

bool CipherCtx::verify_tag(std::span<const uint8_t> expected) const {
    return detail::verify_tag(tag(), expected);
}

std::unique_ptr<CipherCtx> create(Algorithm algo, Mode mode,
    std::span<const uint8_t, 16> key, std::span<const uint8_t, 12> nonce, bool encrypt) {
    validate_parameters(algo, mode);
    return std::make_unique<AesCipherCtx>(mode, key, nonce, encrypt);
}
} // namespace streamcipher::cipher
