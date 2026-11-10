// Runtime-dispatched AES-NI with equivalent portable round operations.
#include "streamcipher/simd/aesni.hpp"
#include "streamcipher/core/aes.hpp"
#include "streamcipher/core/gf.hpp"
#include <cstring>
#include "../detail/wipe_guard.hpp"

#ifdef STREAMCIPHER_AESNI
#include <wmmintrin.h>
#if defined(__GNUC__) || defined(__clang__)
#define SC_AES_TARGET __attribute__((target("aes,sse2")))
#else
#define SC_AES_TARGET
#endif
#endif

namespace streamcipher::simd::aesni {
namespace {
Vec128 software_round(const Vec128& state, const Vec128& key, bool inverse, bool last) noexcept {
    Vec128 shifted{}, result{};
    detail::WipeGuard wipe_shifted(shifted.data, sizeof(shifted.data));
    detail::WipeGuard wipe_result(result.data, sizeof(result.data));
    for (size_t col = 0; col < 4; ++col)
        for (size_t row = 0; row < 4; ++row) {
            const size_t src = ((col + (inverse ? 4 - row : row)) % 4) * 4 + row;
            shifted.data[col * 4 + row] = inverse ? gf::inv_sbox(state.data[src]) : gf::sbox(state.data[src]);
        }
    if (last) result = shifted;
    else for (size_t col = 0; col < 4; ++col) {
        const auto* a = shifted.data + col * 4;
        auto* r = result.data + col * 4;
        for (size_t i = 0; i < 4; ++i) {
            if (inverse)
                r[i] = gf::mul14(a[i]) ^ gf::mul11(a[(i+1)%4]) ^ gf::mul13(a[(i+2)%4]) ^ gf::mul9(a[(i+3)%4]);
            else
                r[i] = gf::xtime(a[i]) ^ gf::mul3(a[(i+1)%4]) ^ a[(i+2)%4] ^ a[(i+3)%4];
        }
    }
    return xor128(result, key);
}

#ifdef STREAMCIPHER_AESNI
SC_AES_TARGET Vec128 hardware_round(const Vec128& state, const Vec128& key, bool inverse, bool last) noexcept {
    auto s = _mm_loadu_si128(reinterpret_cast<const __m128i*>(state.data));
    auto k = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key.data));
    if (inverse) s = last ? _mm_aesdeclast_si128(s, k) : _mm_aesdec_si128(s, k);
    else s = last ? _mm_aesenclast_si128(s, k) : _mm_aesenc_si128(s, k);
    Vec128 out;
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out.data), s);
    return out;
}

template<int Rcon>
SC_AES_TARGET __m128i next_key(__m128i k) noexcept {
    auto t = _mm_aeskeygenassist_si128(k, Rcon);
    t = _mm_shuffle_epi32(t, 0xff);
    auto result = _mm_xor_si128(k, _mm_slli_si128(k, 4));
    result = _mm_xor_si128(result, _mm_slli_si128(k, 8));
    result = _mm_xor_si128(result, _mm_slli_si128(k, 12));
    return _mm_xor_si128(result, t);
}
SC_AES_TARGET void hardware_expand(std::span<const uint8_t, 16> key, std::span<uint8_t, 176> out) noexcept {
    auto k = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key.data()));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out.data()), k);
#define SC_NEXT(I, R) k = next_key<R>(k); _mm_storeu_si128(reinterpret_cast<__m128i*>(out.data() + 16 * I), k)
    SC_NEXT(1, 0x01); SC_NEXT(2, 0x02); SC_NEXT(3, 0x04); SC_NEXT(4, 0x08);
    SC_NEXT(5, 0x10); SC_NEXT(6, 0x20); SC_NEXT(7, 0x40); SC_NEXT(8, 0x80);
    SC_NEXT(9, 0x1b); SC_NEXT(10, 0x36);
#undef SC_NEXT
}
SC_AES_TARGET void hardware_blocks(uint8_t* blocks, size_t count,
    std::span<const uint8_t, 176> keys, bool inverse) noexcept {
    __m128i rk[11];
    detail::WipeGuard wipe(rk, sizeof(rk));
    for (int i = 0; i < 11; ++i) {
        rk[i] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(keys.data() + 16 * i));
        // AESDEC uses the equivalent inverse cipher's transformed middle keys.
        if (inverse && i > 0 && i < 10) rk[i] = _mm_aesimc_si128(rk[i]);
    }
    for (size_t i = 0; i < count; ++i) {
        auto s = _mm_loadu_si128(reinterpret_cast<const __m128i*>(blocks + 16 * i));
        if (inverse) {
            s = _mm_xor_si128(s, rk[10]);
            for (int r = 9; r > 0; --r) s = _mm_aesdec_si128(s, rk[r]);
            s = _mm_aesdeclast_si128(s, rk[0]);
        } else {
            s = _mm_xor_si128(s, rk[0]);
            for (int r = 1; r < 10; ++r) s = _mm_aesenc_si128(s, rk[r]);
            s = _mm_aesenclast_si128(s, rk[10]);
        }
        _mm_storeu_si128(reinterpret_cast<__m128i*>(blocks + 16 * i), s);
    }
}
#endif
Vec128 round(const Vec128& state, const Vec128& key, bool inverse, bool last) noexcept {
#ifdef STREAMCIPHER_AESNI
    if (simd::has_aesni()) return hardware_round(state, key, inverse, last);
#endif
    return software_round(state, key, inverse, last);
}
} // namespace
Vec128 enc_round(const Vec128& s, const Vec128& k) noexcept { return round(s, k, false, false); }
Vec128 enc_round_last(const Vec128& s, const Vec128& k) noexcept { return round(s, k, false, true); }
Vec128 dec_round(const Vec128& s, const Vec128& k) noexcept { return round(s, k, true, false); }
Vec128 dec_round_last(const Vec128& s, const Vec128& k) noexcept { return round(s, k, true, true); }

void expand_key_128(std::span<const uint8_t, 16> key, std::span<uint8_t, 176> out) noexcept {
#ifdef STREAMCIPHER_AESNI
    if (simd::has_aesni()) { hardware_expand(key, out); return; }
#endif
    auto keys = aes::expand_key(key);
    detail::WipeGuard wipe(keys.data(), sizeof(keys));
    std::memcpy(out.data(), keys.data(), 176);
}
void encrypt_blocks(uint8_t* blocks, size_t count, std::span<const uint8_t, 176> keys) noexcept {
#ifdef STREAMCIPHER_AESNI
    if (simd::has_aesni()) { hardware_blocks(blocks, count, keys, false); return; }
#endif
    aes::RoundKeys rk;
    detail::WipeGuard wipe(rk.data(), sizeof(rk));
    std::memcpy(rk.data(), keys.data(), 176);
    for (size_t i = 0; i < count; ++i) aes::encrypt_block(std::span<uint8_t, 16>(blocks + i * 16, 16), rk);
}
void decrypt_blocks(uint8_t* blocks, size_t count, std::span<const uint8_t, 176> keys) noexcept {
#ifdef STREAMCIPHER_AESNI
    if (simd::has_aesni()) { hardware_blocks(blocks, count, keys, true); return; }
#endif
    aes::RoundKeys rk;
    detail::WipeGuard wipe(rk.data(), sizeof(rk));
    std::memcpy(rk.data(), keys.data(), 176);
    for (size_t i = 0; i < count; ++i) aes::decrypt_block(std::span<uint8_t, 16>(blocks + i * 16, 16), rk);
}
} // namespace streamcipher::simd::aesni
