// 将八个 AES 块转置为 128 个位切片字；布局参考 Käsper 和 Schwabe
// 的 CHES 2009 工作。S-box 从位切片提取字节，使用代数实现后写回。
// 未验证的布尔电路保存在 docs/experiments/sbox-circuit.md，不属于运行时代码。

#include "streamcipher/core/bitslice.hpp"
#include "streamcipher/core/gf.hpp"
#include <cstring>
#include "../detail/wipe_guard.hpp"

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
            word |= static_cast<SliceWord>(((val >> bit_in_byte) & 1u) << block);
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
            dst[block * 16 + byte_idx] |= static_cast<uint8_t>(((word >> block) & 1u) << bit_in_byte);
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

// Unverified circuit experiment is archived in docs/experiments/sbox-circuit.md.

// ---- SubBytes ----
// 每个字节位置从位切片提取八个字节，逐字节替换后写回。
// 代数 S-box 避免查表，但不能据此推断机器码的侧信道性质。

namespace {
// Share the representation conversion; select the byte transform at compile time.
template<auto Substitute>
void substitute_bytes(BitSliceState& state) noexcept {
    uint8_t bytes[SLICE_WIDTH];
    detail::WipeGuard wipe(bytes, sizeof(bytes));

    for (int byte_idx = 0; byte_idx < 16; ++byte_idx) {
        // 从 8 个 bit-slice word 里抽出 SLICE_WIDTH 个字节
        std::memset(bytes, 0, SLICE_WIDTH);
        for (int bit = 0; bit < 8; ++bit) {
            SliceWord word = state.bits[byte_idx * 8 + bit];
            for (size_t block = 0; block < SLICE_WIDTH; ++block) {
                bytes[block] |= static_cast<uint8_t>(((word >> block) & 1u) << bit);
            }
        }
        // 过 S-box
        for (size_t b = 0; b < SLICE_WIDTH; ++b) bytes[b] = Substitute(bytes[b]);
        // 塞回去
        for (int bit = 0; bit < 8; ++bit) state.bits[byte_idx * 8 + bit] = 0;
        for (size_t block = 0; block < SLICE_WIDTH; ++block) {
            uint8_t val = bytes[block];
            for (int bit = 0; bit < 8; ++bit) {
                state.bits[byte_idx * 8 + bit] |= static_cast<SliceWord>(((val >> bit) & 1u) << block);
            }
        }
    }
}
} // namespace

void sub_bytes(BitSliceState& state) noexcept {
    substitute_bytes<gf::sbox>(state);
}

void inv_sub_bytes(BitSliceState& state) noexcept {
    substitute_bytes<gf::inv_sbox>(state);
}

// ---- ShiftRows ----
// bits[i*8..i*8+7] 对应逻辑字节 i，与 pack 的顺序一致。

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
            state.bits[byte_idx * 8 + bit] ^= static_cast<SliceWord>(0u - ((k >> bit) & 1u));
        }
    }
}

// ---- 完整的 bit-sliced 加密/解密 ----

void encrypt_blocks(uint8_t* blocks,
                    std::span<const std::array<uint8_t, BLOCK_BYTES>, 11> round_keys) noexcept {
    auto state = pack(std::span<const uint8_t, SLICE_BYTES>(blocks, SLICE_BYTES));
    detail::WipeGuard wipe(state.bits, sizeof(state.bits));
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
    detail::WipeGuard wipe(state.bits, sizeof(state.bits));
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
