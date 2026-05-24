// AES-128 implementation — scalar, bit-sliced, and AES-NI paths
//
// Three execution paths:
//   1. Scalar:     one block at a time, using algebraic S-box (gf::sbox)
//   2. Bit-sliced: SLICE_WIDTH blocks in parallel, Boolean-circuit S-box
//   3. AES-NI:     hardware-accelerated via x86 AES-NI intrinsics
//
// Runtime dispatch selects the fastest available path.

#include "streamcipher/core/aes.hpp"
#include "streamcipher/core/gf.hpp"
#include "streamcipher/core/bitslice.hpp"
#include <cstring>
#include <array>

namespace streamcipher::aes {

// ═══════════════════════════════════════════════════════════════
//  Key Expansion
// ═══════════════════════════════════════════════════════════════

RoundKeys expand_key(std::span<const uint8_t, KEY_SIZE> key) noexcept {
    RoundKeys rk{};
    std::memcpy(rk[0].data(), key.data(), KEY_SIZE);

    // Rcon values for rounds 1..10 = x^(round-1) in GF(2^8)
    static constexpr uint8_t RCON[11] = {
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10,
        0x20, 0x40, 0x80, 0x1b, 0x36
    };

    for (size_t round = 1; round <= ROUNDS; ++round) {
        auto& prev = rk[round - 1];
        auto& curr = rk[round];

        // RotWord: [a0,a1,a2,a3] → [a1,a2,a3,a0]
        // The last 4 bytes of prev are a0,a1,a2,a3 (column 3)
        // Wait — in the standard AES key expansion:
        // w[i] = w[i-4] ^ temp
        // temp = SubWord(RotWord(w[i-1])) ^ Rcon[i/4]
        //
        // For 128-bit key (4 words):
        // w[4] = w[0] ^ SubWord(RotWord(w[3])) ^ Rcon[1]
        // w[5] = w[1] ^ w[4]
        // w[6] = w[2] ^ w[5]
        // w[7] = w[3] ^ w[6]
        //
        // Each word = 4 bytes of column j = bytes [j*4 .. j*4+3]

        // w[round*4] from w[round*4-1] = last word of previous round
        size_t last_word_idx = 3;  // w[round*4 - 1] = prev column 3

        uint8_t temp[4] = {
            prev[last_word_idx * 4 + 1],  // RotWord: skip byte 0
            prev[last_word_idx * 4 + 2],
            prev[last_word_idx * 4 + 3],
            prev[last_word_idx * 4 + 0],  // wrap around
        };
        // SubWord
        for (auto& t : temp) t = gf::sbox(t);
        // XOR with Rcon
        temp[0] ^= RCON[round];

        // First column of new round key
        for (int i = 0; i < 4; ++i) {
            curr[i] = prev[i] ^ temp[i];  // w[round*4] = w[round*4-4] ^ temp
        }
        // Remaining 3 columns
        for (int col = 1; col < 4; ++col) {
            for (int i = 0; i < 4; ++i) {
                curr[col * 4 + i] = prev[col * 4 + i] ^ curr[(col - 1) * 4 + i];
            }
        }
    }
    return rk;
}

// ═══════════════════════════════════════════════════════════════
//  Scalar AES-128 (single block)
// ═══════════════════════════════════════════════════════════════

namespace {

void sub_bytes_scalar(std::span<uint8_t, BLOCK_SIZE> state) noexcept {
    for (auto& byte : state) byte = gf::sbox(byte);
}

void inv_sub_bytes_scalar(std::span<uint8_t, BLOCK_SIZE> state) noexcept {
    for (auto& byte : state) byte = gf::inv_sbox(byte);
}

void shift_rows_scalar(std::span<uint8_t, BLOCK_SIZE> state) noexcept {
    // Row 0 (bytes 0,4,8,12): unchanged
    // Row 1 (bytes 1,5,9,13): left by 1 → (5,9,13,1)
    uint8_t t = state[1];
    state[1]  = state[5];
    state[5]  = state[9];
    state[9]  = state[13];
    state[13] = t;
    // Row 2 (bytes 2,6,10,14): left by 2 → swap (2,10) and (6,14)
    std::swap(state[2], state[10]);
    std::swap(state[6], state[14]);
    // Row 3 (bytes 3,7,11,15): left by 3 = right by 1 → (15,3,7,11)
    t = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7]  = state[3];
    state[3]  = t;
}

void inv_shift_rows_scalar(std::span<uint8_t, BLOCK_SIZE> state) noexcept {
    uint8_t t = state[13];
    state[13] = state[9];
    state[9]  = state[5];
    state[5]  = state[1];
    state[1]  = t;
    std::swap(state[2], state[10]);
    std::swap(state[6], state[14]);
    t = state[3];
    state[3]  = state[7];
    state[7]  = state[11];
    state[11] = state[15];
    state[15] = t;
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
        a[0] = u; a[1] = v; a[2] = w; a[3] = x;
    }
}

void add_round_key_scalar(std::span<uint8_t, BLOCK_SIZE> state,
                          const std::array<uint8_t, BLOCK_SIZE>& rk) noexcept {
    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
        state[i] ^= rk[i];
    }
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

// ═══════════════════════════════════════════════════════════════
//  ECB Convenience Wrappers
// ═══════════════════════════════════════════════════════════════

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

// ═══════════════════════════════════════════════════════════════
//  Bit-sliced Batch Encryption
// ═══════════════════════════════════════════════════════════════

void encrypt_bitsliced(uint8_t* blocks, size_t count,
                       std::span<const uint8_t, KEY_SIZE> key) noexcept {
    auto rk = expand_key(key);

    constexpr size_t B = bitslice::SLICE_WIDTH;
    size_t full_slices = count / B;
    [[maybe_unused]] size_t remainder = count % B;

    // Process full slices
    for (size_t s = 0; s < full_slices; ++s) {
        bitslice::encrypt_blocks(
            blocks + s * B * BLOCK_SIZE,
            std::span<const std::array<uint8_t, BLOCK_SIZE>, 11>(rk)
        );
    }

    // Process remaining blocks with scalar path
    for (size_t i = full_slices * B; i < count; ++i) {
        auto block = std::span<uint8_t, BLOCK_SIZE>(blocks + i * BLOCK_SIZE, BLOCK_SIZE);
        encrypt_block(block, rk);
    }
}

// ═══════════════════════════════════════════════════════════════
//  Fast Path — Runtime Dispatch
// ═══════════════════════════════════════════════════════════════

void encrypt_fast(uint8_t* blocks, size_t count,
                  std::span<const uint8_t, KEY_SIZE> key) noexcept {
    // TODO: Check for AES-NI at runtime; if available, use hardware path.
    // For now, use bit-sliced (which is the best software path).
    encrypt_bitsliced(blocks, count, key);
}

bool has_aesni() noexcept {
#ifdef __AES__
    return true;
#else
    // TODO: Runtime CPUID check
    return false;
#endif
}

} // namespace streamcipher::aes
