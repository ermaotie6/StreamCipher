// bitslice.hpp — 位切片 AES，把 8 个块转置成 128 个 bit-slice word
//
// 原始论文: Käsper & Schwabe, CHES 2009
// 简单说：传统 AES 是一个字节一个字节处理，我们改成每个 bit 位置
// 上 8 个块的值打包成一个 uint8_t（SliceWord），然后所有轮操作
// （SubBytes/ShiftRows/MixColumns/AddRoundKey）都在 bit-slice 域里
// 用布尔电路搞定，全程不查表。

#pragma once

#include <cstdint>
#include <cstddef>
#include <span>
#include <array>

namespace streamcipher::bitslice {

constexpr size_t BLOCK_BYTES = 16;
constexpr size_t BLOCK_BITS  = 128;
constexpr size_t SLICE_WIDTH = 8;     // 一次处理 8 个块
constexpr size_t SLICE_BYTES = SLICE_WIDTH * BLOCK_BYTES;  // 128

// 一个 bit-slice word：8 个块的同一个 bit 位置的值
using SliceWord = uint8_t;

// bit-sliced AES state：128 个 SliceWord，cache-line 对齐
struct alignas(64) BitSliceState {
    SliceWord bits[BLOCK_BITS];
};

// pack: 8 个 16 字节块 → BitSliceState
[[nodiscard]] BitSliceState pack(std::span<const uint8_t, SLICE_BYTES> src) noexcept;

// unpack: BitSliceState → 8 个 16 字节块
void unpack(const BitSliceState& state,
            std::span<uint8_t, SLICE_BYTES> dst) noexcept;

// 状态级布尔运算（给将来纯门电路 S-box 用的）
[[nodiscard]] BitSliceState xor_state(const BitSliceState& a, const BitSliceState& b) noexcept;
[[nodiscard]] BitSliceState and_state(const BitSliceState& a, const BitSliceState& b) noexcept;
[[nodiscard]] BitSliceState not_state(const BitSliceState& a) noexcept;
[[nodiscard]] BitSliceState or_state(const BitSliceState& a, const BitSliceState& b) noexcept;

// AES 轮操作（全部在 bit-sliced 域中）
void sub_bytes(BitSliceState& state) noexcept;
void inv_sub_bytes(BitSliceState& state) noexcept;
void shift_rows(BitSliceState& state) noexcept;
void inv_shift_rows(BitSliceState& state) noexcept;
void mix_columns(BitSliceState& state) noexcept;
void inv_mix_columns(BitSliceState& state) noexcept;
void add_round_key(BitSliceState& state,
                   std::span<const uint8_t, BLOCK_BYTES> key) noexcept;

// 完整的 bit-sliced 加密/解密
void encrypt_blocks(uint8_t* blocks,
                    std::span<const std::array<uint8_t, BLOCK_BYTES>, 11> round_keys) noexcept;
void decrypt_blocks(uint8_t* blocks,
                    std::span<const std::array<uint8_t, BLOCK_BYTES>, 11> round_keys) noexcept;

} // namespace streamcipher::bitslice
