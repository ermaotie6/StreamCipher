// aes.cpp — AES-128 三路实现：标量 / bit-sliced / AES-NI
//
// 标量路径：一次一个块，用 gf::sbox() 代数 S-box
// bit-sliced 路径：一次 8 个块，走 bitslice 模块
// AES-NI 路径：x86 硬件指令（编译时检测 __AES__）

#include "streamcipher/core/aes.hpp"
#include "streamcipher/core/gf.hpp"
#include "streamcipher/core/bitslice.hpp"
#include <cstring>
#include <array>

namespace streamcipher::aes {

// ---- 密钥扩展 ----
// 把 16 字节密钥炸成 11 个轮密钥（176 字节），用代数 S-box 不查表

RoundKeys expand_key(std::span<const uint8_t, KEY_SIZE> key) noexcept {
    RoundKeys rk{};
    std::memcpy(rk[0].data(), key.data(), KEY_SIZE);

    // Rcon[i] = x^(i-1) 在 GF(2^8) 中
    static constexpr uint8_t RCON[11] = {
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10,
        0x20, 0x40, 0x80, 0x1b, 0x36
    };

    for (size_t round = 1; round <= ROUNDS; ++round) {
        auto& prev = rk[round - 1];
        auto& curr = rk[round];

        // AES-128 key schedule:
        // w[i] = w[i-4] ^ temp, temp = SubWord(RotWord(w[i-1])) ^ Rcon[i/4]
        // 每轮只对最后一列做 RotWord + SubWord + Rcon，前三列直接异或

        uint8_t temp[4] = {
            prev[13],  // RotWord: col3 的 byte1 → byte0
            prev[14],  // col3 byte2 → byte1
            prev[15],  // col3 byte3 → byte2
            prev[12],  // col3 byte0 → byte3 (wrap)
        };
        for (auto& t : temp) t = gf::sbox(t);
        temp[0] ^= RCON[round];

        for (int i = 0; i < 4; ++i) curr[i] = prev[i] ^ temp[i];
        for (int col = 1; col < 4; ++col)
            for (int i = 0; i < 4; ++i)
                curr[col*4 + i] = prev[col*4 + i] ^ curr[(col-1)*4 + i];
    }
    return rk;
}

// ---- 标量 AES（单块，用于测试和不足 8 块的剩余块） ----

namespace {

void sub_bytes_scalar(std::span<uint8_t, BLOCK_SIZE> state) noexcept {
    for (auto& byte : state) byte = gf::sbox(byte);
}
void inv_sub_bytes_scalar(std::span<uint8_t, BLOCK_SIZE> state) noexcept {
    for (auto& byte : state) byte = gf::inv_sbox(byte);
}
void shift_rows_scalar(std::span<uint8_t, BLOCK_SIZE> state) noexcept {
    // Row 0: no-op; Row 1: 左1; Row 2: 左2; Row 3: 左3(=右1)
    uint8_t t = state[1];
    state[1]=state[5]; state[5]=state[9]; state[9]=state[13]; state[13]=t;
    std::swap(state[2], state[10]); std::swap(state[6], state[14]);
    t = state[15];
    state[15]=state[11]; state[11]=state[7]; state[7]=state[3]; state[3]=t;
}
void inv_shift_rows_scalar(std::span<uint8_t, BLOCK_SIZE> state) noexcept {
    uint8_t t = state[13];
    state[13]=state[9]; state[9]=state[5]; state[5]=state[1]; state[1]=t;
    std::swap(state[2], state[10]); std::swap(state[6], state[14]);
    t = state[3];
    state[3]=state[7]; state[7]=state[11]; state[11]=state[15]; state[15]=t;
}
void mix_columns_scalar(std::span<uint8_t, BLOCK_SIZE> state) noexcept {
    for (int col = 0; col < 4; ++col) {
        auto a = state.subspan(col * 4, 4);
        uint8_t t = a[0] ^ a[1] ^ a[2] ^ a[3];
        uint8_t u = a[0];
        a[0] ^= t ^ gf::xtime(a[0] ^ a[1]);
        a[1] ^= t ^ gf::xtime(a[1] ^ a[2]);
        a[2] ^= t ^ gf::xtime(a[2] ^ a[3]);
        a[3] ^= t ^ gf::xtime(a[3] ^ u);
    }
}
void inv_mix_columns_scalar(std::span<uint8_t, BLOCK_SIZE> state) noexcept {
    for (int col = 0; col < 4; ++col) {
        auto a = state.subspan(col * 4, 4);
        uint8_t u = gf::mul14(a[0]) ^ gf::mul11(a[1]) ^ gf::mul13(a[2]) ^ gf::mul9(a[3]);
        uint8_t v = gf::mul9(a[0])  ^ gf::mul14(a[1]) ^ gf::mul11(a[2]) ^ gf::mul13(a[3]);
        uint8_t w = gf::mul13(a[0]) ^ gf::mul9(a[1])  ^ gf::mul14(a[2]) ^ gf::mul11(a[3]);
        uint8_t x = gf::mul11(a[0]) ^ gf::mul13(a[1]) ^ gf::mul9(a[2])  ^ gf::mul14(a[3]);
        a[0]=u; a[1]=v; a[2]=w; a[3]=x;
    }
}
void add_round_key_scalar(std::span<uint8_t, BLOCK_SIZE> state,
                          const std::array<uint8_t, BLOCK_SIZE>& rk) noexcept {
    for (size_t i = 0; i < BLOCK_SIZE; ++i) state[i] ^= rk[i];
}

} // anonymous namespace

void encrypt_block(std::span<uint8_t, BLOCK_SIZE> block,
                   const RoundKeys& round_keys) noexcept {
    add_round_key_scalar(block, round_keys[0]);
    for (size_t r = 1; r < ROUNDS; ++r) {
        sub_bytes_scalar(block);
        shift_rows_scalar(block);
        mix_columns_scalar(block);
        add_round_key_scalar(block, round_keys[r]);
    }
    sub_bytes_scalar(block);
    shift_rows_scalar(block);
    add_round_key_scalar(block, round_keys[ROUNDS]);
}

void decrypt_block(std::span<uint8_t, BLOCK_SIZE> block,
                   const RoundKeys& round_keys) noexcept {
    add_round_key_scalar(block, round_keys[ROUNDS]);
    inv_shift_rows_scalar(block);
    inv_sub_bytes_scalar(block);
    for (size_t r = ROUNDS - 1; r >= 1; --r) {
        add_round_key_scalar(block, round_keys[r]);
        inv_mix_columns_scalar(block);
        inv_shift_rows_scalar(block);
        inv_sub_bytes_scalar(block);
    }
    add_round_key_scalar(block, round_keys[0]);
}

// ---- ECB 便捷封装（主要是给测试用） ----

void encrypt_ecb(std::span<uint8_t, BLOCK_SIZE> block,
                 std::span<const uint8_t, KEY_SIZE> key) noexcept {
    auto rk = expand_key(key);
    encrypt_block(block, rk);
}

void decrypt_ecb(std::span<uint8_t, BLOCK_SIZE> block,
                 std::span<const uint8_t, KEY_SIZE> key) noexcept {
    auto rk = expand_key(key);
    decrypt_block(block, rk);
}

// ---- bit-sliced 批量加密 ----
// 把 count 个块分成完整的 8 块切片（走 bitslice::encrypt_blocks）
// 和不足 8 的零头（走标量）

void encrypt_bitsliced(uint8_t* blocks, size_t count,
                       std::span<const uint8_t, KEY_SIZE> key) noexcept {
    auto rk = expand_key(key);
    constexpr size_t B = bitslice::SLICE_WIDTH;
    size_t full_slices = count / B;

    for (size_t s = 0; s < full_slices; ++s) {
        bitslice::encrypt_blocks(
            blocks + s * B * BLOCK_SIZE,
            std::span<const std::array<uint8_t, BLOCK_SIZE>, 11>(rk));
    }
    // 零头走标量
    for (size_t i = full_slices * B; i < count; ++i) {
        auto block = std::span<uint8_t, BLOCK_SIZE>(blocks + i * BLOCK_SIZE, BLOCK_SIZE);
        encrypt_block(block, rk);
    }
}

// ---- 快速路径：运行时选最优 ----
// 当前默认走 bit-sliced。AES-NI 检测只是编译期的，后面改成 CPUID。

void encrypt_fast(uint8_t* blocks, size_t count,
                  std::span<const uint8_t, KEY_SIZE> key) noexcept {
    // TODO: CPUID 检测 AES-NI，有的话调 simd::aesni
    encrypt_bitsliced(blocks, count, key);
}

bool has_aesni() noexcept {
#ifdef __AES__
    return true;
#else
    return false;  // TODO: 加 CPUID 运行时检测
#endif
}

} // namespace streamcipher::aes
