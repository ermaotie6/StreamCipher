// GF(2^8) 有限域运算，纯位运算，不查表
//
// AES 标准不可约多项式: x^8 + x^4 + x^3 + x + 1 → 0x1B
// 标量运算可在编译期求值；编译后的侧信道性质需要在目标平台评估。

#pragma once

#include <cstdint>
#include <cstddef>
#include <bit>
#include <array>

namespace streamcipher::gf {

constexpr uint8_t IRREDUCIBLE_POLY = 0x1B;  // x^8 + x^4 + x^3 + x + 1
using GF8 = uint8_t;

// -- 核心运算 --

// GF(2^8) 乘法，移位加算法，固定 8 次迭代。
// &-(b&1) 条件异或写法参考 BearSSL；不保证编译后的机器码性质。
[[nodiscard]] constexpr GF8 mul(GF8 a, GF8 b) noexcept {
    GF8 result = 0;
    for (int i = 0; i < 8; ++i) {
        result ^= a & -(b & 1);            // 如果 b 的 LSB 是 1，XOR a
        const auto mask = static_cast<uint8_t>(0u - (a >> 7));
        a = static_cast<uint8_t>((a << 1) ^ (IRREDUCIBLE_POLY & mask));
        b >>= 1;
    }
    return result;
}

// 乘法逆元：a^254（费马小定理），使用固定指数的快速幂。
[[nodiscard]] constexpr GF8 inv(GF8 a) noexcept {
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
    const auto mask = static_cast<uint8_t>(0u - (a >> 7));
    return static_cast<uint8_t>((a << 1) ^ (IRREDUCIBLE_POLY & mask));
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
// 用 std::rotr 实现位偏移。

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
// 逆仿射变换不包含 a_i 项。
[[nodiscard]] constexpr GF8 inv_sbox(GF8 a) noexcept {
    GF8 x = std::rotr(a, 2) ^ std::rotr(a, 5) ^ std::rotr(a, 7) ^ 0x05;
    return inv(x);
}

// -- 批量运算：允许完全原地操作，部分重叠缓冲区不支持 --

void mul_batch(GF8* dst, const GF8* a,
               const GF8* b, size_t count) noexcept;
void inv_batch(GF8* dst, const GF8* src,
               size_t count) noexcept;
void sbox_batch(GF8* dst, const GF8* src,
                size_t count) noexcept;
void inv_sbox_batch(GF8* dst, const GF8* src,
                    size_t count) noexcept;

} // namespace streamcipher::gf
