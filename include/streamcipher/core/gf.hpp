// GF(2^8) 有限域运算，纯位运算，不查表
//
// AES 标准不可约多项式: x^8 + x^4 + x^3 + x + 1 → 0x1B
// 所有函数都是 constexpr + 常数时间，编译器优化后直接内联

#pragma once

#include <cstdint>
#include <cstddef>
#include <bit>
#include <array>

namespace streamcipher::gf {

constexpr uint8_t IRREDUCIBLE_POLY = 0x1B;  // x^8 + x^4 + x^3 + x + 1
using GF8 = uint8_t;

// -- 核心运算 --

// GF(2^8) 乘法，标准移位加，固定 8 次迭代，常数时间
// 那个 &-(b&1) 的小技巧是无分支条件异或，来自 BearSSL
[[nodiscard]] constexpr GF8 mul(GF8 a, GF8 b) noexcept {
    GF8 result = 0;
    for (int i = 0; i < 8; ++i) {
        result ^= a & -(b & 1);            // 如果 b 的 LSB 是 1，XOR a
        uint8_t carry = a & 0x80;
        a = (a << 1) ^ (carry ? IRREDUCIBLE_POLY : 0);
        b >>= 1;
    }
    return result;
}

// 乘法逆元：a^254（费马小定理），快速幂，常数时间
[[nodiscard]] constexpr GF8 inv(GF8 a) noexcept {
    if (a == 0) return 0;    // 0 没有逆元，约定返回 0
    GF8 x = a;
    GF8 result = 1;
    for (int i = 7; i >= 0; --i) {
        result = mul(result, result);      // 平方
        if ((254 >> i) & 1)
            result = mul(result, x);       // 乘以基数
    }
    return result;
}

// xtime: 乘以 x（即 0x02），MixColumns 专用快速路径
[[nodiscard]] constexpr GF8 xtime(GF8 a) noexcept {
    return (a & 0x80) ? ((a << 1) ^ IRREDUCIBLE_POLY) : (a << 1);
}

// 逆 MixColumns 用的系数：9, 11, 13, 14（都用 xtime 叠加，不调通用乘法）
[[nodiscard]] constexpr GF8 mul3(GF8 a)  noexcept { return xtime(a) ^ a; }
[[nodiscard]] constexpr GF8 mul9(GF8 a)  noexcept { return xtime(xtime(xtime(a))) ^ a; }
[[nodiscard]] constexpr GF8 mul11(GF8 a) noexcept { return xtime(xtime(xtime(a))) ^ xtime(a) ^ a; }
[[nodiscard]] constexpr GF8 mul13(GF8 a) noexcept { return xtime(xtime(xtime(a))) ^ xtime(xtime(a)) ^ a; }
[[nodiscard]] constexpr GF8 mul14(GF8 a) noexcept { return xtime(xtime(xtime(a))) ^ xtime(xtime(a)) ^ xtime(a); }

// -- AES S-box，代数实现，不查表 --
//
// S(x) = Affine(GF_inv(x))
// 仿射变换：b_i = a_i ^ a_{i+4} ^ a_{i+5} ^ a_{i+6} ^ a_{i+7} ^ c_i
// c = 0x63
//
// 用 std::rotr 实现各位的偏移，注意是右旋不是左旋（踩过这个坑）

[[nodiscard]] constexpr GF8 sbox(GF8 a) noexcept {
    GF8 inv_a = inv(a);
    GF8 result = inv_a;
    result ^= std::rotr(inv_a, 4);   // a_{i+4}
    result ^= std::rotr(inv_a, 5);   // a_{i+5}
    result ^= std::rotr(inv_a, 6);   // a_{i+6}
    result ^= std::rotr(inv_a, 7);   // a_{i+7}
    result ^= 0x63;                  // 常数项
    return result;
}

// 逆 S-box：先过逆仿射，再过 GF 逆元
// 逆仿射: b_i' = a_{i+2} ^ a_{i+5} ^ a_{i+7} ^ d_i, d=0x05
// 注意这里没有 a_i 项（跟正向不一样，又一个踩过的坑）
[[nodiscard]] constexpr GF8 inv_sbox(GF8 a) noexcept {
    GF8 x = std::rotr(a, 2) ^ std::rotr(a, 5) ^ std::rotr(a, 7) ^ 0x05;
    return inv(x);
}

// -- 批量运算 --

void mul_batch(GF8* __restrict dst, const GF8* __restrict a,
               const GF8* __restrict b, size_t count) noexcept;
void inv_batch(GF8* __restrict dst, const GF8* __restrict src,
               size_t count) noexcept;
void sbox_batch(GF8* __restrict dst, const GF8* __restrict src,
                size_t count) noexcept;
void inv_sbox_batch(GF8* __restrict dst, const GF8* __restrict src,
                    size_t count) noexcept;

} // namespace streamcipher::gf
