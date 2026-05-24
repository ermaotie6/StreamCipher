// SIMD abstraction layer — with SSE4.1/AVX2 intrinsics when available
#include "streamcipher/simd/simd.hpp"
#include <cstring>

#ifdef __SSE4_1__
#include <smmintrin.h>
#endif
#ifdef __AVX2__
#include <immintrin.h>
#endif

namespace streamcipher::simd {

// ═══════════════════════════════════════════════════════════════
//  CPU Feature Detection
// ═══════════════════════════════════════════════════════════════

bool has_sse41() noexcept {
#ifdef __SSE4_1__
    return true;
#else
    return false;
#endif
}

bool has_avx2() noexcept {
#ifdef __AVX2__
    return true;
#else
    return false;
#endif
}

bool has_aesni() noexcept {
#ifdef __AES__
    return true;
#else
    return false;
#endif
}

// ═══════════════════════════════════════════════════════════════
//  128-bit Operations
// ═══════════════════════════════════════════════════════════════

Vec128 xor128(const Vec128& a, const Vec128& b) noexcept {
#ifdef __SSE4_1__
    __m128i va = _mm_loadu_si128(reinterpret_cast<const __m128i*>(a.data));
    __m128i vb = _mm_loadu_si128(reinterpret_cast<const __m128i*>(b.data));
    __m128i vr = _mm_xor_si128(va, vb);
    Vec128 r;
    _mm_storeu_si128(reinterpret_cast<__m128i*>(r.data), vr);
    return r;
#else
    Vec128 r;
    for (int i = 0; i < 16; ++i) r.data[i] = a.data[i] ^ b.data[i];
    return r;
#endif
}

Vec128 gf_mul128(const Vec128& a, const Vec128& b) noexcept {
    // GF(2^8) lane-wise multiplication — no SIMD instruction for this directly
    Vec128 r;
    for (int i = 0; i < 16; ++i) {
        // Use the gf::mul function
        uint8_t prod = 0;
        uint8_t x = a.data[i], y = b.data[i];
        for (int bit = 0; bit < 8; ++bit) {
            prod ^= x & -(y & 1);
            uint8_t carry = x & 0x80;
            x = (x << 1) ^ (carry ? uint8_t(0x1B) : uint8_t(0));
            y >>= 1;
        }
        r.data[i] = prod;
    }
    return r;
}

Vec128 shift_bytes_left(const Vec128& a, unsigned shift) noexcept {
    Vec128 r;
    shift %= 16;
    for (int i = 0; i < 16; ++i) {
        r.data[i] = a.data[(i + shift) % 16];
    }
    return r;
}

Vec128 load128(const uint8_t* ptr) noexcept {
#ifdef __SSE4_1__
    Vec128 v;
    _mm_storeu_si128(reinterpret_cast<__m128i*>(v.data),
                     _mm_loadu_si128(reinterpret_cast<const __m128i*>(ptr)));
    return v;
#else
    Vec128 v;
    std::memcpy(v.data, ptr, 16);
    return v;
#endif
}

void store128(uint8_t* ptr, const Vec128& v) noexcept {
#ifdef __SSE4_1__
    _mm_storeu_si128(reinterpret_cast<__m128i*>(ptr),
                     _mm_loadu_si128(reinterpret_cast<const __m128i*>(v.data)));
#else
    std::memcpy(ptr, v.data, 16);
#endif
}

// ═══════════════════════════════════════════════════════════════
//  256-bit Operations
// ═══════════════════════════════════════════════════════════════

#ifdef STREAMCIPHER_SIMD

Vec256 xor256(const Vec256& a, const Vec256& b) noexcept {
#ifdef __AVX2__
    __m256i va = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(a.data));
    __m256i vb = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(b.data));
    __m256i vr = _mm256_xor_si256(va, vb);
    Vec256 r;
    _mm256_storeu_si256(reinterpret_cast<__m256i*>(r.data), vr);
    return r;
#else
    Vec256 r;
    for (int i = 0; i < 32; ++i) r.data[i] = a.data[i] ^ b.data[i];
    return r;
#endif
}

Vec256 load256(const uint8_t* ptr) noexcept {
#ifdef __AVX2__
    Vec256 v;
    _mm256_storeu_si256(reinterpret_cast<__m256i*>(v.data),
                        _mm256_loadu_si256(reinterpret_cast<const __m256i*>(ptr)));
    return v;
#else
    Vec256 v;
    std::memcpy(v.data, ptr, 32);
    return v;
#endif
}

void store256(uint8_t* ptr, const Vec256& v) noexcept {
#ifdef __AVX2__
    _mm256_storeu_si256(reinterpret_cast<__m256i*>(ptr),
                        _mm256_loadu_si256(reinterpret_cast<const __m256i*>(v.data)));
#else
    std::memcpy(ptr, v.data, 32);
#endif
}

Vec256 gf_mul256(const Vec256& a, const Vec256& b) noexcept {
    Vec256 r;
    for (int i = 0; i < 32; ++i) {
        uint8_t prod = 0;
        uint8_t x = a.data[i], y = b.data[i];
        for (int bit = 0; bit < 8; ++bit) {
            prod ^= x & -(y & 1);
            uint8_t carry = x & 0x80;
            x = (x << 1) ^ (carry ? uint8_t(0x1B) : uint8_t(0));
            y >>= 1;
        }
        r.data[i] = prod;
    }
    return r;
}

#endif // STREAMCIPHER_SIMD

} // namespace streamcipher::simd
