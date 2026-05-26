// bitslice.cpp --- 把8个AES块转置成128个bit-slice word，然后一轮一轮撸
//
// 核心思路来自 Käsper & Schwabe 的 CHES 2009 论文。简单说就是把
// 传统AES的"按字节处理"改成"按bit位置处理"——每个bit位置上8个块的值
// 塞进一个uint8_t里，然后所有轮操作都用布尔电路搞定，不用查表。
//
// 当前 S-box 走的是 gf::sbox() 的标量路径（每字节提取→算→塞回去），
// 虽然不如纯布尔电路快，但好歹是常数时间+无查表，先跑通了再说。
// #if 0 里面有一套 Canright GF((2^4)^2) 布尔电路的实现，调通了再切过去。

#include "streamcipher/core/bitslice.hpp"
#include "streamcipher/core/gf.hpp"
#include <cstring>

namespace streamcipher::bitslice {

// ---- pack / unpack ----

BitSliceState pack(std::span<const uint8_t, SLICE_BYTES> src) noexcept {
    BitSliceState state{};
    for (int bit = 0; bit < 128; ++bit) {
        SliceWord word = 0;
        int byte_idx = bit / 8;
        int bit_in_byte = bit % 8;
        for (size_t block = 0; block < SLICE_WIDTH; ++block) {
            uint8_t val = src[block * 16 + byte_idx];
            if ((val >> bit_in_byte) & 1) {
                word |= (SliceWord(1) << block);
            }
        }
        state.bits[bit] = word;
    }
    return state;
}

void unpack(const BitSliceState& state,
            std::span<uint8_t, SLICE_BYTES> dst) noexcept {
    std::memset(dst.data(), 0, SLICE_BYTES);
    for (int bit = 0; bit < 128; ++bit) {
        SliceWord word = state.bits[bit];
        int byte_idx = bit / 8;
        int bit_in_byte = bit % 8;
        for (size_t block = 0; block < SLICE_WIDTH; ++block) {
            if ((word >> block) & 1) {
                dst[block * 16 + byte_idx] |= (1u << bit_in_byte);
            }
        }
    }
}

// ---- 状态级别的布尔运算（给将来纯电路S-box用的） ----

BitSliceState xor_state(const BitSliceState& a, const BitSliceState& b) noexcept {
    BitSliceState r;
    for (int i = 0; i < 128; ++i) r.bits[i] = a.bits[i] ^ b.bits[i];
    return r;
}

BitSliceState and_state(const BitSliceState& a, const BitSliceState& b) noexcept {
    BitSliceState r;
    for (int i = 0; i < 128; ++i) r.bits[i] = a.bits[i] & b.bits[i];
    return r;
}

BitSliceState not_state(const BitSliceState& a) noexcept {
    BitSliceState r;
    for (int i = 0; i < 128; ++i) r.bits[i] = ~a.bits[i];
    return r;
}

BitSliceState or_state(const BitSliceState& a, const BitSliceState& b) noexcept {
    BitSliceState r;
    for (int i = 0; i < 128; ++i) r.bits[i] = a.bits[i] | b.bits[i];
    return r;
}

// ================================================================
// Canright GF((2^4)^2) 布尔电路 S-box --- 矩阵还没调对，先封着
// 思路是对的：把 GF(2^8) 的逆元映射到 GF((2^4)^2) 里算，再映回来
// 这样整个 SubBytes 就是一套 AND/XOR 门电路，完全不用查表
// 问题是 T_transform 和 T_inv_transform 那两套 4×8 矩阵的系数
// 我算了好几遍都对不上 NIST 的测试向量，所以先走标量路径
// ================================================================

namespace {

#if 0  // ---- 下面这套布尔电路矩阵没调通，先封印 ----

// GF(2^4) 的四则运算，每个元素用 4 个 SliceWord 表示 (w3,w2,w1,w0)

using GF4 = std::array<SliceWord, 4>;

// GF(2^4) 乘法，模 x^4+x+1
[[nodiscard]] GF4 gf4_mul(const GF4& a, const GF4& b) noexcept {
    SliceWord a0=a[0], a1=a[1], a2=a[2], a3=a[3];
    SliceWord b0=b[0], b1=b[1], b2=b[2], b3=b[3];

    SliceWord t0 = a3 & b1;
    SliceWord t1 = a2 & b2;
    SliceWord t2 = a1 & b3;
    SliceWord t3 = a0 & b0;
    SliceWord t5 = (a2 ^ a3) & b2;
    SliceWord t6 = (a1 ^ a2) & b3;
    SliceWord t7 = a1 & b0;
    SliceWord t8 = a2 & b0;
    SliceWord t9 = a3 & b0;
    SliceWord tA = a2 & b1;
    SliceWord tB = a1 & b2;
    SliceWord tC = (a0 ^ a3) & b2;
    SliceWord tD = (a2 ^ a3) & b3;

    return {
        t9 ^ tA ^ tB ^ (a0 ^ a3) & b3,
        t8 ^ (a0 ^ a3) & b1 ^ t5 ^ t6,
        t7 ^ t1  ^ tC ^ tD,
        t3 ^ t0  ^ t1 ^ t2
    };
}

// GF(2^4) 平方
[[nodiscard]] GF4 gf4_sq(const GF4& a) noexcept {
    return {a[3], a[1] ^ a[3], a[2], a[0] ^ a[2]};
}

// GF(2^4) 逆元，暴力真值表化简出来的
[[nodiscard]] GF4 gf4_inv(const GF4& a) noexcept {
    SliceWord a0=a[0], a1=a[1], a2=a[2], a3=a[3];

    SliceWord t0 = a1 ^ a2 ^ a3 ^ (a0 & a1 & a2) ^ (a0 & a1 & a3) ^ (a0 & a2 & a3);
    SliceWord t1 = a0 ^ a1 ^ a0 & a2 ^ a1 & a2 ^ a0 & a1 & a3 ^ a0 & a2 & a3;
    SliceWord t2 = a0 ^ a1 ^ a2 ^ a0 & a3 ^ a1 & a3 ^ a0 & a1 & a2 ^ a0 & a2 & a3;
    SliceWord t3 = a1 ^ a2 ^ a3 ^ a0 & a1 ^ a0 & a2 ^ a1 & a2 ^ a0 & a1 & a3;

    return {t3, t2, t1, t0};
}

// 乘常数 λ=0x6（GF(2^4) 里面 ω^2+ω 的结果）
[[nodiscard]] GF4 gf4_mul_lambda(const GF4& a) noexcept {
    SliceWord a0=a[0], a1=a[1], a2=a[2], a3=a[3];
    return {a2 ^ a0, a1 ^ a3, a0 ^ a3, a3};
}

// GF((2^4)^2) 的元素：高4位 + 低4位
struct GF8Composite { GF4 hi, lo; };

// GF((2^4)^2) 的逆元： (a_h*y + a_l)^(-1) = a_h*d*y + (a_h+a_l)*d
// 其中 d = (a_h^2*λ + a_h*a_l + a_l^2)^(-1)
[[nodiscard]] GF8Composite gf8c_inv(const GF8Composite& x) noexcept {
    GF4 ah2   = gf4_sq(x.hi);
    GF4 al2   = gf4_sq(x.lo);
    GF4 ahal  = gf4_mul(x.hi, x.lo);
    GF4 tmp   = gf4_mul_lambda(ah2);
    GF4 sum   = { tmp[3]^ahal[3]^al2[3], tmp[2]^ahal[2]^al2[2],
                  tmp[1]^ahal[1]^al2[1], tmp[0]^ahal[0]^al2[0] };
    GF4 d     = gf4_inv(sum);
    GF4 r_hi  = gf4_mul(x.hi, d);
    GF4 ah_al = { x.hi[3]^x.lo[3], x.hi[2]^x.lo[2],
                  x.hi[1]^x.lo[1], x.hi[0]^x.lo[0] };
    GF4 r_lo  = gf4_mul(ah_al, d);
    return {r_hi, r_lo};
}

// 同构映射 T: GF(2^8) → GF((2^4)^2)
// 这里的两套 4×8 矩阵是 Canright 论文里给的标准形式
// 但我算了几遍跟 NIST 向量对不上，怀疑是 λ 的取值或者基的选择有问题
// TODO: 对着论文重新推一遍矩阵系数

void T_transform(SliceWord b7, SliceWord b6, SliceWord b5, SliceWord b4,
                 SliceWord b3, SliceWord b2, SliceWord b1, SliceWord b0,
                 GF4& ah, GF4& al) noexcept {
    ah[3] = b7 ^ b5;
    ah[2] = b7 ^ b6 ^ b4 ^ b3 ^ b2 ^ b1;
    ah[1] = b7 ^ b5 ^ b3 ^ b2;
    ah[0] = b7 ^ b6 ^ b3 ^ b2 ^ b1 ^ b0;
    al[3] = b7 ^ b6 ^ b5 ^ b3;
    al[2] = b6 ^ b4;
    al[1] = b7 ^ b6 ^ b5 ^ b4 ^ b3;
    al[0] = b6 ^ b5 ^ b4 ^ b2 ^ b1 ^ b0;
}

void T_inv_transform(const GF4& ah, const GF4& al,
                     SliceWord& b7, SliceWord& b6, SliceWord& b5, SliceWord& b4,
                     SliceWord& b3, SliceWord& b2, SliceWord& b1, SliceWord& b0) noexcept {
    b7 = ah[3] ^ ah[2] ^ ah[1] ^ al[3] ^ al[0];
    b6 = ah[2] ^ ah[0] ^ al[3] ^ al[1];
    b5 = ah[0] ^ al[2] ^ al[0];
    b4 = ah[3] ^ ah[2] ^ ah[0] ^ al[2] ^ al[1];
    b3 = ah[3] ^ ah[1] ^ ah[0] ^ al[2] ^ al[1] ^ al[0];
    b2 = ah[3] ^ ah[2] ^ al[3];
    b1 = ah[3] ^ ah[2] ^ ah[0] ^ al[3] ^ al[0];
    b0 = ah[3] ^ ah[2] ^ ah[1] ^ ah[0] ^ al[3] ^ al[2] ^ al[1];
}

// 正向仿射，c=0x63
void affine_transform(SliceWord& b7, SliceWord& b6, SliceWord& b5, SliceWord& b4,
                      SliceWord& b3, SliceWord& b2, SliceWord& b1, SliceWord& b0) noexcept {
    SliceWord a7=b7, a6=b6, a5=b5, a4=b4, a3=b3, a2=b2, a1=b1, a0=b0;
    SliceWord ONES = ~SliceWord(0), ZERO = SliceWord(0);
    b0 = a0 ^ a4 ^ a5 ^ a6 ^ a7 ^ ONES;
    b1 = a1 ^ a5 ^ a6 ^ a7 ^ a0 ^ ONES;
    b2 = a2 ^ a6 ^ a7 ^ a0 ^ a1 ^ ZERO;
    b3 = a3 ^ a7 ^ a0 ^ a1 ^ a2 ^ ZERO;
    b4 = a4 ^ a0 ^ a1 ^ a2 ^ a3 ^ ZERO;
    b5 = a5 ^ a1 ^ a2 ^ a3 ^ a4 ^ ONES;
    b6 = a6 ^ a2 ^ a3 ^ a4 ^ a5 ^ ONES;
    b7 = a7 ^ a3 ^ a4 ^ a5 ^ a6 ^ ZERO;
}

void sbox_circuit(SliceWord& b7, SliceWord& b6, SliceWord& b5, SliceWord& b4,
                  SliceWord& b3, SliceWord& b2, SliceWord& b1, SliceWord& b0) noexcept {
    GF4 ah, al;
    T_transform(b7, b6, b5, b4, b3, b2, b1, b0, ah, al);
    GF8Composite x = {ah, al};
    GF8Composite inv_x = gf8c_inv(x);
    T_inv_transform(inv_x.hi, inv_x.lo, b7, b6, b5, b4, b3, b2, b1, b0);
    affine_transform(b7, b6, b5, b4, b3, b2, b1, b0);
}

// 逆S-box：先逆仿射（d=0x05），再走同样的 GF((2^4)^2) 逆元
void inv_sbox_circuit(SliceWord& b7, SliceWord& b6, SliceWord& b5, SliceWord& b4,
                      SliceWord& b3, SliceWord& b2, SliceWord& b1, SliceWord& b0) noexcept {
    SliceWord a7=b7, a6=b6, a5=b5, a4=b4, a3=b3, a2=b2, a1=b1, a0=b0;
    SliceWord ONES = ~SliceWord(0), ZERO = SliceWord(0);
    SliceWord s0 = a2 ^ a5 ^ a7,  s1 = a3 ^ a6 ^ a0;
    SliceWord s2 = a4 ^ a7 ^ a1,  s3 = a5 ^ a0 ^ a2;
    SliceWord s4 = a6 ^ a1 ^ a3,  s5 = a7 ^ a2 ^ a4;
    SliceWord s6 = a0 ^ a3 ^ a5,  s7 = a1 ^ a4 ^ a6;
    b0 = s0 ^ ONES;  b1 = s1 ^ ZERO;  b2 = s2 ^ ONES;  b3 = s3 ^ ZERO;
    b4 = s4 ^ ZERO;  b5 = s5 ^ ZERO;  b6 = s6 ^ ZERO;  b7 = s7 ^ ZERO;

    GF4 ah, al;
    T_transform(b7, b6, b5, b4, b3, b2, b1, b0, ah, al);
    GF8Composite x = {ah, al};
    GF8Composite inv_x = gf8c_inv(x);
    T_inv_transform(inv_x.hi, inv_x.lo, b7, b6, b5, b4, b3, b2, b1, b0);
}

#endif // 布尔电路 S-box (矩阵没调通)

} // anonymous namespace

// ---- SubBytes：用标量 gf::sbox() 先跑着 ----
//
// 原理很简单：把每个 byte 位置从 8 个 bit-slice word 里抽出来 8 个字节，
// 每个字节过一遍 gf::sbox()（本身就是常数时间的），再塞回去。
// 虽然不如纯门电路快，但正确性优先，后面再优化。

void sub_bytes(BitSliceState& state) noexcept {
    uint8_t bytes[SLICE_WIDTH];

    for (int byte_idx = 0; byte_idx < 16; ++byte_idx) {
        // 从 8 个 bit-slice word 里抽出 SLICE_WIDTH 个字节
        std::memset(bytes, 0, SLICE_WIDTH);
        for (int bit = 0; bit < 8; ++bit) {
            SliceWord word = state.bits[byte_idx * 8 + bit];
            for (size_t block = 0; block < SLICE_WIDTH; ++block) {
                if ((word >> block) & 1) bytes[block] |= (1u << bit);
            }
        }
        // 过 S-box
        for (size_t b = 0; b < SLICE_WIDTH; ++b) bytes[b] = gf::sbox(bytes[b]);
        // 塞回去
        for (int bit = 0; bit < 8; ++bit) state.bits[byte_idx * 8 + bit] = 0;
        for (size_t block = 0; block < SLICE_WIDTH; ++block) {
            uint8_t val = bytes[block];
            for (int bit = 0; bit < 8; ++bit) {
                if ((val >> bit) & 1)
                    state.bits[byte_idx * 8 + bit] |= (SliceWord(1) << block);
            }
        }
    }
}

void inv_sub_bytes(BitSliceState& state) noexcept {
    uint8_t bytes[SLICE_WIDTH];
    for (int byte_idx = 0; byte_idx < 16; ++byte_idx) {
        std::memset(bytes, 0, SLICE_WIDTH);
        for (int bit = 0; bit < 8; ++bit) {
            SliceWord word = state.bits[byte_idx * 8 + bit];
            for (size_t block = 0; block < SLICE_WIDTH; ++block) {
                if ((word >> block) & 1) bytes[block] |= (1u << bit);
            }
        }
        for (size_t b = 0; b < SLICE_WIDTH; ++b) bytes[b] = gf::inv_sbox(bytes[b]);
        for (int bit = 0; bit < 8; ++bit) state.bits[byte_idx * 8 + bit] = 0;
        for (size_t block = 0; block < SLICE_WIDTH; ++block) {
            uint8_t val = bytes[block];
            for (int bit = 0; bit < 8; ++bit) {
                if ((val >> bit) & 1)
                    state.bits[byte_idx * 8 + bit] |= (SliceWord(1) << block);
            }
        }
    }
}

// ---- ShiftRows ----
// 因为现在 bits[i*8..i*8+7] 对应的是逻辑字节 i，所以直接按字节索引交换就行
// （之前踩过一个坑：pack 里写了 15-i 的逆序布局，导致这里全乱套，已修）

void shift_rows(BitSliceState& state) noexcept {
    // Row 1: 字节 1,5,9,13 → 5,9,13,1
    {
        SliceWord tmp[8];
        for (int b = 0; b < 8; ++b) tmp[b] = state.bits[1*8 + b];
        for (int b = 0; b < 8; ++b) state.bits[1*8 + b]  = state.bits[5*8 + b];
        for (int b = 0; b < 8; ++b) state.bits[5*8 + b]  = state.bits[9*8 + b];
        for (int b = 0; b < 8; ++b) state.bits[9*8 + b]  = state.bits[13*8 + b];
        for (int b = 0; b < 8; ++b) state.bits[13*8 + b] = tmp[b];
    }
    // Row 2: 两两交换
    {
        for (int b = 0; b < 8; ++b) std::swap(state.bits[2*8 + b], state.bits[10*8 + b]);
        for (int b = 0; b < 8; ++b) std::swap(state.bits[6*8 + b], state.bits[14*8 + b]);
    }
    // Row 3: 3,7,11,15 → 15,3,7,11 (左移3=右移1)
    {
        SliceWord tmp[8];
        for (int b = 0; b < 8; ++b) tmp[b] = state.bits[15*8 + b];
        for (int b = 0; b < 8; ++b) state.bits[15*8 + b] = state.bits[11*8 + b];
        for (int b = 0; b < 8; ++b) state.bits[11*8 + b] = state.bits[7*8 + b];
        for (int b = 0; b < 8; ++b) state.bits[7*8 + b]  = state.bits[3*8 + b];
        for (int b = 0; b < 8; ++b) state.bits[3*8 + b]  = tmp[b];
    }
}

void inv_shift_rows(BitSliceState& state) noexcept {
    // Row 1: undone
    {
        SliceWord tmp[8];
        for (int b = 0; b < 8; ++b) tmp[b] = state.bits[1*8 + b];
        for (int b = 0; b < 8; ++b) state.bits[1*8 + b]  = state.bits[13*8 + b];
        for (int b = 0; b < 8; ++b) state.bits[13*8 + b] = state.bits[9*8 + b];
        for (int b = 0; b < 8; ++b) state.bits[9*8 + b]  = state.bits[5*8 + b];
        for (int b = 0; b < 8; ++b) state.bits[5*8 + b]  = tmp[b];
    }
    // Row 2: swap back
    {
        for (int b = 0; b < 8; ++b) std::swap(state.bits[2*8 + b], state.bits[10*8 + b]);
        for (int b = 0; b < 8; ++b) std::swap(state.bits[6*8 + b], state.bits[14*8 + b]);
    }
    // Row 3: undone
    {
        SliceWord tmp[8];
        for (int b = 0; b < 8; ++b) tmp[b] = state.bits[3*8 + b];
        for (int b = 0; b < 8; ++b) state.bits[3*8 + b]  = state.bits[7*8 + b];
        for (int b = 0; b < 8; ++b) state.bits[7*8 + b]  = state.bits[11*8 + b];
        for (int b = 0; b < 8; ++b) state.bits[11*8 + b] = state.bits[15*8 + b];
        for (int b = 0; b < 8; ++b) state.bits[15*8 + b] = tmp[b];
    }
}

// ---- MixColumns ----
// 列混合的矩阵乘： [2 3 1 1; 1 2 3 1; 1 1 2 3; 3 1 1 2]
// s0' = 2*s0 ⊕ 3*s1 ⊕ 1*s2 ⊕ 1*s3 = xtime(s0) ⊕ (s1⊕xtime(s1)) ⊕ s2 ⊕ s3
// 这里的关键是 xtime 在 bit-sliced 域里怎么算——见 xtime_slice

namespace {

// xtime 的 bit-sliced 版本：乘以 x 在 GF(2^8) 中，模 x^8+x^4+x^3+x+1
// 推导：x*a = a<<1，如果 a7=1 则异或 0x1B
// 所以输出 bit 和输入 bit 的关系是线性的：
//   xt0 = b7
//   xt1 = b0 ^ b7     (b0 移到了 bit1，加上反馈 b7)
//   xt2 = b1
//   xt3 = b2 ^ b7     (b2→b3 加上反馈，因为 0x1B = 00011011，反馈在 bit4,3,1,0)
//   实际上 0x1B = x^4+x^3+x+1，所以反馈打到 bit4, bit3, bit1, bit0
//   也就是 xt3 = b2 ^ b7, xt4 = b3 ^ b7, xt1 = b0 ^ b7, xt0 = b7
void xtime_slice(SliceWord* src, SliceWord* dst) noexcept {
    SliceWord b0=src[0], b1=src[1], b2=src[2], b3=src[3];
    SliceWord b4=src[4], b5=src[5], b6=src[6], b7=src[7];
    dst[0] = b7;
    dst[1] = b0 ^ b7;
    dst[2] = b1;
    dst[3] = b2 ^ b7;
    dst[4] = b3 ^ b7;
    dst[5] = b4;
    dst[6] = b5;
    dst[7] = b6;
}

// 处理一列（4个字节 × 8个bit-slice = 32个SliceWord）
void mix_column(BitSliceState& state, int col) noexcept {
    SliceWord* s[4];
    for (int i = 0; i < 4; ++i) s[i] = &state.bits[(col * 4 + i) * 8];

    SliceWord xt[4][8];
    for (int i = 0; i < 4; ++i) xtime_slice(s[i], xt[i]);

    SliceWord tmp[4][8];
    for (int b = 0; b < 8; ++b) {
        tmp[0][b] = xt[0][b] ^ s[1][b] ^ xt[1][b] ^ s[2][b] ^ s[3][b];
        tmp[1][b] = s[0][b] ^ xt[1][b] ^ s[2][b] ^ xt[2][b] ^ s[3][b];
        tmp[2][b] = s[0][b] ^ s[1][b] ^ xt[2][b] ^ s[3][b] ^ xt[3][b];
        tmp[3][b] = s[0][b] ^ xt[0][b] ^ s[1][b] ^ s[2][b] ^ xt[3][b];
    }
    for (int i = 0; i < 4; ++i)
        for (int b = 0; b < 8; ++b)
            s[i][b] = tmp[i][b];
}

// 逆 MixColumns: [14 11 13 9; 9 14 11 13; 13 9 14 11; 11 13 9 14]
// 系数 9,11,13,14 通过 xtime 叠加实现
void inv_mix_column(BitSliceState& state, int col) noexcept {
    SliceWord* s[4];
    for (int i = 0; i < 4; ++i) s[i] = &state.bits[(col * 4 + i) * 8];

    SliceWord xt[4][8], xt2[4][8], xt3[4][8];
    for (int i = 0; i < 4; ++i) {
        xtime_slice(s[i], xt[i]);
        xtime_slice(xt[i], xt2[i]);
        xtime_slice(xt2[i], xt3[i]);
    }

    // 9a = xt3(a) ^ a, 11a = xt3(a) ^ xt(a) ^ a
    // 13a = xt3(a) ^ xt2(a) ^ a, 14a = xt3(a) ^ xt2(a) ^ xt(a)
    SliceWord m9[4][8], m11[4][8], m13[4][8], m14[4][8];
    for (int i = 0; i < 4; ++i) {
        for (int b = 0; b < 8; ++b) {
            m9[i][b]  = xt3[i][b] ^ s[i][b];
            m11[i][b] = xt3[i][b] ^ xt[i][b] ^ s[i][b];
            m13[i][b] = xt3[i][b] ^ xt2[i][b] ^ s[i][b];
            m14[i][b] = xt3[i][b] ^ xt2[i][b] ^ xt[i][b];
        }
    }

    SliceWord tmp[4][8];
    for (int b = 0; b < 8; ++b) {
        tmp[0][b] = m14[0][b] ^ m11[1][b] ^ m13[2][b] ^ m9[3][b];
        tmp[1][b] = m9[0][b]  ^ m14[1][b] ^ m11[2][b] ^ m13[3][b];
        tmp[2][b] = m13[0][b] ^ m9[1][b]  ^ m14[2][b] ^ m11[3][b];
        tmp[3][b] = m11[0][b] ^ m13[1][b] ^ m9[2][b]  ^ m14[3][b];
    }
    for (int i = 0; i < 4; ++i)
        for (int b = 0; b < 8; ++b)
            s[i][b] = tmp[i][b];
}

} // anonymous namespace

void mix_columns(BitSliceState& state) noexcept {
    for (int col = 0; col < 4; ++col) mix_column(state, col);
}

void inv_mix_columns(BitSliceState& state) noexcept {
    for (int col = 0; col < 4; ++col) inv_mix_column(state, col);
}

// ---- AddRoundKey ----
// 轮密钥的每个 byte 要异或到所有 8 个块的对应 byte 上。
// 在 bit-sliced 域里就是：key 某 bit 为 1 → 翻转整个 SliceWord。

void add_round_key(BitSliceState& state,
                   std::span<const uint8_t, BLOCK_BYTES> key) noexcept {
    for (int byte_idx = 0; byte_idx < 16; ++byte_idx) {
        uint8_t k = key[byte_idx];
        for (int bit = 0; bit < 8; ++bit) {
            if ((k >> bit) & 1) state.bits[byte_idx * 8 + bit] ^= 0xFF;
        }
    }
}

// ---- 完整的 bit-sliced 加密/解密 ----

void encrypt_blocks(uint8_t* blocks,
                    std::span<const std::array<uint8_t, BLOCK_BYTES>, 11> round_keys) noexcept {
    auto state = pack(std::span<const uint8_t, SLICE_BYTES>(blocks, SLICE_BYTES));
    add_round_key(state, round_keys[0]);
    for (int round = 1; round < 10; ++round) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round_keys[round]);
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, round_keys[10]);
    unpack(state, std::span<uint8_t, SLICE_BYTES>(blocks, SLICE_BYTES));
}

void decrypt_blocks(uint8_t* blocks,
                    std::span<const std::array<uint8_t, BLOCK_BYTES>, 11> round_keys) noexcept {
    auto state = pack(std::span<const uint8_t, SLICE_BYTES>(blocks, SLICE_BYTES));
    add_round_key(state, round_keys[10]);
    inv_shift_rows(state);
    inv_sub_bytes(state);
    for (int round = 9; round >= 1; --round) {
        add_round_key(state, round_keys[round]);
        inv_mix_columns(state);
        inv_shift_rows(state);
        inv_sub_bytes(state);
    }
    add_round_key(state, round_keys[0]);
    unpack(state, std::span<uint8_t, SLICE_BYTES>(blocks, SLICE_BYTES));
}

} // namespace streamcipher::bitslice
