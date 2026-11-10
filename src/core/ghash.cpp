#include "ghash.hpp"
#include "../detail/wipe_guard.hpp"

namespace streamcipher::detail {
void GHash::update(const Block& block) noexcept {
    for (size_t i = 0; i < state_.size(); ++i) state_[i] ^= block[i];
    Block v = key_, z{};
    WipeGuard wipe_v(v.data(), v.size()), wipe_z(z.data(), z.size());
    // SP 800-38D multiplication, most significant bit first.
    for (size_t bit = 0; bit < 128; ++bit) {
        const auto mask = static_cast<uint8_t>(0u - ((state_[bit / 8] >> (7 - bit % 8)) & 1u));
        for (size_t i = 0; i < 16; ++i) z[i] ^= v[i] & mask;
        const auto reduce = static_cast<uint8_t>(0u - (v[15] & 1u));
        for (size_t i = 15; i > 0; --i)
            v[i] = static_cast<uint8_t>((v[i] >> 1) | (v[i - 1] << 7));
        v[0] = static_cast<uint8_t>((v[0] >> 1) ^ (0xe1 & reduce));
    }
    state_ = z;
}
}
