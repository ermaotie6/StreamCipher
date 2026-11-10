#pragma once
#include "streamcipher/core/parameters.hpp"
#include "streamcipher/memory/secure.hpp"
#include <array>

namespace streamcipher::detail {
using Block = std::array<uint8_t, cipher::BLOCK_SIZE>;
// Private, allocation-free GHASH primitive. Padding and length policy stay in the mode.
class GHash {
public:
    ~GHash() { memory::secure_zero(key_); memory::secure_zero(state_); }
    GHash() = default;
    GHash(const GHash&) = delete;
    GHash& operator=(const GHash&) = delete;
    void set_key(const Block& key) noexcept { key_ = key; state_.fill(0); }
    void update(const Block& block) noexcept;
    [[nodiscard]] const Block& value() const noexcept { return state_; }
private:
    Block key_{}, state_{};
};
}
