#include "streamcipher/core/aes.hpp"
#include "streamcipher/simd/aesni.hpp"
#include "../detail/wipe_guard.hpp"

namespace streamcipher::aes {
// ---- 快速路径：运行时选最优 ----
// 运行时优先 AES-NI；不可用时走 bit-sliced 和标量尾块。

void encrypt_fast(uint8_t* blocks, size_t count,
                  std::span<const uint8_t, KEY_SIZE> key) noexcept {
    if (has_aesni()) {
        std::array<uint8_t, 176> rk;
        detail::WipeGuard wipe(rk.data(), rk.size());
        simd::aesni::expand_key_128(key, rk);
        simd::aesni::encrypt_blocks(blocks, count, rk);
    } else {
        encrypt_bitsliced(blocks, count, key);
    }
}

bool has_aesni() noexcept {
#ifdef STREAMCIPHER_AESNI
    return simd::has_aesni();
#else
    return false;
#endif
}

} // namespace streamcipher::aes
