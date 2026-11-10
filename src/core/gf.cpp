// gf.cpp — GF(2^8) 批量运算
#include "streamcipher/core/gf.hpp"
#include <cstring>

namespace streamcipher::gf {

// ── Batch Operations ────────────────────────────────────────

void mul_batch(GF8* dst, const GF8* a,
               const GF8* b, size_t count) noexcept {
    for (size_t i = 0; i < count; ++i) {
        dst[i] = mul(a[i], b[i]);
    }
}

void inv_batch(GF8* dst, const GF8* src,
               size_t count) noexcept {
    for (size_t i = 0; i < count; ++i) {
        dst[i] = inv(src[i]);
    }
}

void sbox_batch(GF8* dst, const GF8* src,
                size_t count) noexcept {
    for (size_t i = 0; i < count; ++i) {
        dst[i] = sbox(src[i]);
    }
}

void inv_sbox_batch(GF8* dst, const GF8* src,
                    size_t count) noexcept {
    for (size_t i = 0; i < count; ++i) {
        dst[i] = inv_sbox(src[i]);
    }
}

} // namespace streamcipher::gf
