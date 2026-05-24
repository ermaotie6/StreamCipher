// Galois Field GF(2^8) — batch and bitwise implementations
#include "streamcipher/core/gf.hpp"
#include <cstring>

namespace streamcipher::gf {

// ── Batch Operations ────────────────────────────────────────

void mul_batch(GF8* __restrict dst, const GF8* __restrict a,
               const GF8* __restrict b, size_t count) noexcept {
    for (size_t i = 0; i < count; ++i) {
        dst[i] = mul(a[i], b[i]);
    }
}

void inv_batch(GF8* __restrict dst, const GF8* __restrict src,
               size_t count) noexcept {
    for (size_t i = 0; i < count; ++i) {
        dst[i] = inv(src[i]);
    }
}

void sbox_batch(GF8* __restrict dst, const GF8* __restrict src,
                size_t count) noexcept {
    for (size_t i = 0; i < count; ++i) {
        dst[i] = sbox(src[i]);
    }
}

void inv_sbox_batch(GF8* __restrict dst, const GF8* __restrict src,
                    size_t count) noexcept {
    for (size_t i = 0; i < count; ++i) {
        dst[i] = inv_sbox(src[i]);
    }
}

} // namespace streamcipher::gf
