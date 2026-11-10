// simd.cpp — SIMD 抽象层，x86 SSE4.1 / AVX2 有就用，没有就走标量回退
//
// 这里用条件编译在 SSE/AVX 内联和标量循环之间切换，不用运行时 dispatch
// （因为 AES 的吞吐瓶颈不在这几个 helper 函数上）

#include "streamcipher/simd/simd.hpp"
#include <cstring>
#include "streamcipher/core/gf.hpp"
#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
#include <intrin.h>
#endif

#if defined(STREAMCIPHER_SIMD) && defined(__SSE4_1__)
#include <smmintrin.h>
#endif
#if defined(STREAMCIPHER_SIMD) && defined(__AVX2__)
#include <immintrin.h>
#endif

namespace streamcipher::simd {

// -- CPU 特性检测（运行时缓存，AVX2 同时检查 OS 状态支持） --

namespace {
struct Features { bool sse41 = false, avx2 = false, aesni = false; };
Features detect_features() noexcept {
    Features f;
#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
    int regs[4]{};
    __cpuid(regs, 0);
    const int max_leaf = regs[0];
    if (max_leaf < 1) return f;
    __cpuidex(regs, 1, 0);
    f.sse41 = (regs[2] & (1 << 19)) != 0;
    f.aesni = (regs[2] & (1 << 25)) != 0;
    const bool os_avx = (regs[2] & (1 << 27)) && (regs[2] & (1 << 28));
    if (os_avx && (_xgetbv(0) & 6) == 6 && max_leaf >= 7) {
        __cpuidex(regs, 7, 0);
        f.avx2 = (regs[1] & (1 << 5)) != 0;
    }
#elif (defined(__GNUC__) || defined(__clang__)) && (defined(__x86_64__) || defined(__i386__))
    __builtin_cpu_init();
    f.sse41 = __builtin_cpu_supports("sse4.1");
    f.avx2 = __builtin_cpu_supports("avx2");
    f.aesni = __builtin_cpu_supports("aes");
#endif
    return f;
}
const Features& features() noexcept {
    static const Features f = detect_features();
    return f;
}
}
bool has_sse41() noexcept { return features().sse41; }
bool has_avx2() noexcept { return features().avx2; }
bool has_aesni() noexcept { return features().aesni; }

// -- 128-bit 操作 --

Vec128 xor128(const Vec128& a, const Vec128& b) noexcept {
#if defined(STREAMCIPHER_SIMD) && defined(__SSE4_1__)
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
    // GF(2^8) lane-wise 乘法 —— 没有直接的 SIMD 指令，走标量循环
    Vec128 r;
    for (int i = 0; i < 16; ++i) {
        r.data[i] = gf::mul(a.data[i], b.data[i]);
    }
    return r;
}

Vec128 shift_bytes_left(const Vec128& a, unsigned shift) noexcept {
    Vec128 r;
    shift %= 16;
    for (int i = 0; i < 16; ++i) r.data[i] = a.data[(i + shift) % 16];
    return r;
}

Vec128 load128(const uint8_t* ptr) noexcept {
#if defined(STREAMCIPHER_SIMD) && defined(__SSE4_1__)
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
#if defined(STREAMCIPHER_SIMD) && defined(__SSE4_1__)
    _mm_storeu_si128(reinterpret_cast<__m128i*>(ptr),
                     _mm_loadu_si128(reinterpret_cast<const __m128i*>(v.data)));
#else
    std::memcpy(ptr, v.data, 16);
#endif
}

// -- 256-bit 操作 (AVX2) --


Vec256 xor256(const Vec256& a, const Vec256& b) noexcept {
#if defined(STREAMCIPHER_SIMD) && defined(__AVX2__)
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
#if defined(STREAMCIPHER_SIMD) && defined(__AVX2__)
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
#if defined(STREAMCIPHER_SIMD) && defined(__AVX2__)
    _mm256_storeu_si256(reinterpret_cast<__m256i*>(ptr),
                        _mm256_loadu_si256(reinterpret_cast<const __m256i*>(v.data)));
#else
    std::memcpy(ptr, v.data, 32);
#endif
}

Vec256 gf_mul256(const Vec256& a, const Vec256& b) noexcept {
    Vec256 r;
    for (int i = 0; i < 32; ++i) {
        r.data[i] = gf::mul(a.data[i], b.data[i]);
    }
    return r;
}


} // namespace streamcipher::simd
