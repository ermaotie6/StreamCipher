// aesni.cpp — x86 AES-NI 硬件加速
// 如果有 __AES__ 宏就上 _mm_aesenc_si128 等指令，否则走标量回退
#include "streamcipher/simd/aesni.hpp"
#include "streamcipher/core/aes.hpp"
#include <cstring>

#ifdef STREAMCIPHER_AESNI
#include <wmmintrin.h>
#include <emmintrin.h>
#endif

namespace streamcipher::simd::aesni {

// -- 单轮操作：有 AES-NI 就用指令，没有就 XOR 糊弄过去（标量回退）--

Vec128 enc_round(const Vec128& state, const Vec128& rk) noexcept {
#ifdef STREAMCIPHER_AESNI
    __m128i vs = _mm_loadu_si128(reinterpret_cast<const __m128i*>(state.data));
    __m128i vr = _mm_loadu_si128(reinterpret_cast<const __m128i*>(rk.data));
    __m128i ve = _mm_aesenc_si128(vs, vr);
    Vec128 r; _mm_storeu_si128(reinterpret_cast<__m128i*>(r.data), ve);
    return r;
#else
    return xor128(state, rk);
#endif
}

Vec128 enc_round_last(const Vec128& state, const Vec128& rk) noexcept {
#ifdef STREAMCIPHER_AESNI
    __m128i vs = _mm_loadu_si128(reinterpret_cast<const __m128i*>(state.data));
    __m128i vr = _mm_loadu_si128(reinterpret_cast<const __m128i*>(rk.data));
    __m128i ve = _mm_aesenclast_si128(vs, vr);
    Vec128 r; _mm_storeu_si128(reinterpret_cast<__m128i*>(r.data), ve);
    return r;
#else
    return xor128(state, rk);
#endif
}

Vec128 dec_round(const Vec128& state, const Vec128& rk) noexcept {
#ifdef STREAMCIPHER_AESNI
    __m128i vs = _mm_loadu_si128(reinterpret_cast<const __m128i*>(state.data));
    __m128i vr = _mm_loadu_si128(reinterpret_cast<const __m128i*>(rk.data));
    __m128i vd = _mm_aesdec_si128(vs, vr);
    Vec128 r; _mm_storeu_si128(reinterpret_cast<__m128i*>(r.data), vd);
    return r;
#else
    return xor128(state, rk);
#endif
}

Vec128 dec_round_last(const Vec128& state, const Vec128& rk) noexcept {
#ifdef STREAMCIPHER_AESNI
    __m128i vs = _mm_loadu_si128(reinterpret_cast<const __m128i*>(state.data));
    __m128i vr = _mm_loadu_si128(reinterpret_cast<const __m128i*>(rk.data));
    __m128i vd = _mm_aesdeclast_si128(vs, vr);
    Vec128 r; _mm_storeu_si128(reinterpret_cast<__m128i*>(r.data), vd);
    return r;
#else
    return xor128(state, rk);
#endif
}

// -- AESKEYGENASSIST 密钥扩展 --
// 坑：_mm_aeskeygenassist_si128 第二个参数必须编译期常量，不能传变量。
// 所以用 switch 把 10 个 rcon 值硬编码展开。

void expand_key_128(std::span<const uint8_t, 16> key,
                    std::span<uint8_t, 176> rk) noexcept {
#ifdef STREAMCIPHER_AESNI
    __m128i k = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key.data()));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(rk.data()), k);

    for (int round = 0; round < 10; ++round) {
        int rcon;
        switch (round) {
            case 0: rcon = 0x01; break;  case 1: rcon = 0x02; break;
            case 2: rcon = 0x04; break;  case 3: rcon = 0x08; break;
            case 4: rcon = 0x10; break;  case 5: rcon = 0x20; break;
            case 6: rcon = 0x40; break;  case 7: rcon = 0x80; break;
            case 8: rcon = 0x1B; break;  default: rcon = 0x36; break;
        }
        __m128i tmp = _mm_aeskeygenassist_si128(k, rcon);
        tmp = _mm_shuffle_epi32(tmp, 0xFF);

        __m128i next = k;
        next = _mm_xor_si128(next, _mm_slli_si128(next, 4));
        next = _mm_xor_si128(next, _mm_slli_si128(next, 4));
        next = _mm_xor_si128(next, _mm_slli_si128(next, 4));
        k = _mm_xor_si128(next, tmp);

        _mm_storeu_si128(reinterpret_cast<__m128i*>(rk.data() + (round + 1) * 16), k);
    }
#else
    auto round_keys = aes::expand_key(key);
    std::memcpy(rk.data(), round_keys.data(), 176);
#endif
}

// -- 批量加密/解密 --

void encrypt_blocks(uint8_t* blocks, size_t count,
                    std::span<const uint8_t, 176> round_keys) noexcept {
#ifdef STREAMCIPHER_AESNI
    __m128i rk[11];
    for (int i = 0; i < 11; ++i)
        rk[i] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(round_keys.data() + i*16));
    for (size_t i = 0; i < count; ++i) {
        __m128i state = _mm_loadu_si128(reinterpret_cast<const __m128i*>(blocks + i*16));
        state = _mm_xor_si128(state, rk[0]);
        for (int r = 1; r < 10; ++r) state = _mm_aesenc_si128(state, rk[r]);
        state = _mm_aesenclast_si128(state, rk[10]);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(blocks + i*16), state);
    }
#else
    aes::RoundKeys rk;
    std::memcpy(rk.data(), round_keys.data(), 176);
    for (size_t i = 0; i < count; ++i)
        aes::encrypt_block(std::span<uint8_t,16>(blocks + i*16, 16), rk);
#endif
}

void decrypt_blocks(uint8_t* blocks, size_t count,
                    std::span<const uint8_t, 176> round_keys) noexcept {
#ifdef STREAMCIPHER_AESNI
    __m128i rk[11];
    for (int i = 0; i < 11; ++i)
        rk[i] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(round_keys.data() + i*16));
    for (size_t i = 0; i < count; ++i) {
        __m128i state = _mm_loadu_si128(reinterpret_cast<const __m128i*>(blocks + i*16));
        state = _mm_xor_si128(state, rk[10]);
        for (int r = 9; r >= 1; --r) state = _mm_aesdec_si128(state, rk[r]);
        state = _mm_aesdeclast_si128(state, rk[0]);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(blocks + i*16), state);
    }
#else
    aes::RoundKeys rk;
    std::memcpy(rk.data(), round_keys.data(), 176);
    for (size_t i = 0; i < count; ++i)
        aes::decrypt_block(std::span<uint8_t,16>(blocks + i*16, 16), rk);
#endif
}

} // namespace streamcipher::simd::aesni
