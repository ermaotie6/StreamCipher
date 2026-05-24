// Cipher modes — CTR and GCM (Galois/Counter Mode)
//
// CTR: simple counter mode, keystream XOR
// GCM: authenticated encryption combining CTR with GHASH (GF(2^128))

#include "streamcipher/core/cipher.hpp"
#include "streamcipher/core/gf.hpp"
#include <cstring>
#include <algorithm>

namespace streamcipher::cipher {

// ═══════════════════════════════════════════════════════════════
//  GHASH — Galois Hash in GF(2^128)
// ═══════════════════════════════════════════════════════════════
//
// GF(2^128) with irreducible polynomial: x^128 + x^7 + x^2 + x + 1
// Elements stored as two 64-bit words (big-endian byte order)

namespace {

struct GF128 {
    uint64_t hi;
    uint64_t lo;
};

// Multiply in GF(2^128) using the standard shift-and-add algorithm.
// The GCM irreducible polynomial has the constant term in bit 0 of the hi word.
// This is constant-time (no data-dependent branches).
[[nodiscard]] GF128 gf128_mul(const GF128& a, const GF128& b) noexcept {
    GF128 result = {0, 0};
    uint64_t v_hi = a.hi;
    uint64_t v_lo = a.lo;
    uint64_t z_hi = b.hi;
    uint64_t z_lo = b.lo;

    // Process 128 bits
    for (int i = 0; i < 128; ++i) {
        // If LSB of z is 1, XOR v into result
        uint64_t mask = -(z_lo & 1);  // 0 or ~0
        result.lo ^= (v_lo & mask);
        result.hi ^= (v_hi & mask);

        // Shift z right by 1
        z_lo = (z_lo >> 1) | (z_hi << 63);
        z_hi >>= 1;

        // Multiply v by x (left shift with reduction)
        uint64_t carry = v_hi >> 63;  // bit 127 overflows
        v_hi = (v_hi << 1) | (v_lo >> 63);
        v_lo <<= 1;
        // If carry, XOR with R = x^128 + x^7 + x^2 + x + 1
        // R = 0xE1 << 56 = 0xE100000000000000 (lower 64 bits of the polynomial)
        // The polynomial is: x^128 + x^7 + x^2 + x + 1
        // In the GCM bit reflection: R = 11100001 << 56 = 0xE100000000000000
        uint64_t reduce = -(carry & 1);
        v_lo ^= (0xE100000000000000ULL & reduce);
    }
    return result;
}

// Convert a 16-byte block (big-endian interpreted) to GF128
[[nodiscard]] GF128 bytes_to_gf128(const uint8_t* bytes) noexcept {
    GF128 r;
    r.hi = 0;
    r.lo = 0;
    for (int i = 0; i < 8; ++i) {
        r.hi = (r.hi << 8) | bytes[i];
    }
    for (int i = 8; i < 16; ++i) {
        r.lo = (r.lo << 8) | bytes[i];
    }
    return r;
}

// Convert GF128 to 16 bytes (big-endian)
void gf128_to_bytes(const GF128& x, uint8_t* bytes) noexcept {
    uint64_t hi = x.hi;
    uint64_t lo = x.lo;
    for (int i = 7; i >= 0; --i) {
        bytes[i] = static_cast<uint8_t>(hi & 0xFF);
        hi >>= 8;
    }
    for (int i = 15; i >= 8; --i) {
        bytes[i] = static_cast<uint8_t>(lo & 0xFF);
        lo >>= 8;
    }
}

} // anonymous namespace

// ═══════════════════════════════════════════════════════════════
//  CTR Mode Cipher Context
// ═══════════════════════════════════════════════════════════════

namespace {

class CtrCipherCtx : public CipherCtx {
public:
    CtrCipherCtx(std::span<const uint8_t, 16> key,
                 std::span<const uint8_t, 12> nonce) {
        algo_ = Algorithm::AES_128;
        mode_ = Mode::CTR;
        std::memcpy(key_, key.data(), 16);
        // Counter block: first 12 bytes = nonce, last 4 bytes = counter (0)
        std::memcpy(counter_, nonce.data(), 12);
        counter_[12] = counter_[13] = counter_[14] = counter_[15] = 0;
        round_keys_ = aes::expand_key(std::span<const uint8_t, 16>(key_, 16));
    }

    void update(std::span<const uint8_t> input,
                std::span<uint8_t> output) override {
        std::array<uint8_t, 16> keystream;
        size_t offset = 0;

        while (offset < input.size()) {
            // Generate keystream block
            std::memcpy(keystream.data(), counter_, 16);
            aes::encrypt_block(std::span<uint8_t, 16>(keystream), round_keys_);

            // XOR with input
            size_t chunk = std::min(size_t(16), input.size() - offset);
            for (size_t i = 0; i < chunk; ++i) {
                output[offset + i] = input[offset + i] ^ keystream[i];
            }
            offset += chunk;

            // Increment 32-bit counter (big-endian)
            for (int i = 15; i >= 12; --i) {
                if (++counter_[i] != 0) break;
            }
        }
    }

    void finalize() override {
        // CTR mode has no finalization
    }

    std::span<const uint8_t> tag() const override {
        return {};
    }

private:
    alignas(64) uint8_t key_[16];
    alignas(64) uint8_t counter_[16];
    aes::RoundKeys round_keys_;
};

// ═══════════════════════════════════════════════════════════════
//  GCM Mode Cipher Context
// ═══════════════════════════════════════════════════════════════

class GcmCipherCtx : public CipherCtx {
public:
    GcmCipherCtx(std::span<const uint8_t, 16> key,
                 std::span<const uint8_t, 12> nonce) {
        algo_ = Algorithm::AES_128;
        mode_ = Mode::GCM;
        std::memcpy(key_, key.data(), 16);
        std::memcpy(nonce_, nonce.data(), 12);
        round_keys_ = aes::expand_key(std::span<const uint8_t, 16>(key_, 16));

        // Compute H = AES_K(0^128) — the hash subkey
        std::memset(h_block_, 0, 16);
        aes::encrypt_block(std::span<uint8_t, 16>(h_block_), round_keys_);
        H_ = bytes_to_gf128(h_block_);

        // Initialize counter: nonce || counter=1
        std::memcpy(counter_, nonce.data(), 12);
        counter_[12] = counter_[13] = counter_[14] = 0;
        counter_[15] = 1;

        // Compute J0 (initial counter): for 96-bit nonce, J0 = nonce || 0^31 || 1
        // J0 is aes-encrypted to get the initial GHASH XOR mask
        uint8_t j0[16];
        std::memcpy(j0, nonce.data(), 12);
        j0[12] = j0[13] = j0[14] = 0;
        j0[15] = 1;
        aes::encrypt_block(std::span<uint8_t, 16>(j0), round_keys_);
        j0_ = bytes_to_gf128(j0);
    }

    void update(std::span<const uint8_t> input,
                std::span<uint8_t> output) override {
        // Encrypt with CTR
        std::array<uint8_t, 16> keystream;
        std::array<uint8_t, 16> cipher_block;
        size_t offset = 0;

        while (offset < input.size()) {
            // Use absolute position to compute counter
            uint64_t abs_pos = len_ct_ + offset;
            size_t block_num = abs_pos / 16;
            size_t byte_in_block = abs_pos % 16;

            set_counter(block_num + 1);  // +1 because counter[0] is J0

            std::memcpy(keystream.data(), counter_, 16);
            aes::encrypt_block(std::span<uint8_t, 16>(keystream), round_keys_);

            size_t chunk = std::min(size_t(16) - byte_in_block, input.size() - offset);
            for (size_t i = 0; i < chunk; ++i) {
                output[offset + i] = input[offset + i] ^ keystream[byte_in_block + i];
                cipher_block[i] = output[offset + i];
            }
            for (size_t i = chunk; i < 16; ++i) cipher_block[i] = 0;

            GF128 cb = bytes_to_gf128(cipher_block.data());
            auth_state_ = gf128_mul(gf128_xor(auth_state_, cb), H_);

            offset += chunk;
        }
        len_ct_ += input.size();
    }

    void finalize() override {
        // Final GHASH: append len(A) || len(C) in bits as 64-bit big-endian
        uint8_t len_block[16] = {0};
        // len_ct_ in bits as big-endian 64-bit at bytes 8-15
        uint64_t bits = len_ct_ * 8;
        for (int i = 15; i >= 8; --i) {
            len_block[i] = static_cast<uint8_t>(bits & 0xFF);
            bits >>= 8;
        }
        GF128 lb = bytes_to_gf128(len_block);
        auth_state_ = gf128_mul(gf128_xor(auth_state_, lb), H_);

        // Final tag = auth_state XOR J0
        GF128 tag_val = gf128_xor(auth_state_, j0_);
        gf128_to_bytes(tag_val, tag_);
    }

    std::span<const uint8_t> tag() const override {
        return std::span<const uint8_t>(tag_, 16);
    }

private:
    static GF128 gf128_xor(const GF128& a, const GF128& b) noexcept {
        return {a.hi ^ b.hi, a.lo ^ b.lo};
    }

    void set_counter(uint64_t block_num) noexcept {
        uint32_t ctr = static_cast<uint32_t>(block_num);
        counter_[12] = (ctr >> 24) & 0xFF;
        counter_[13] = (ctr >> 16) & 0xFF;
        counter_[14] = (ctr >> 8) & 0xFF;
        counter_[15] = ctr & 0xFF;
    }

    alignas(64) uint8_t key_[16];
    alignas(64) uint8_t nonce_[12];
    alignas(64) uint8_t counter_[16];
    alignas(64) uint8_t h_block_[16];
    aes::RoundKeys round_keys_;
    GF128 H_;
    GF128 auth_state_{0, 0};
    GF128 j0_{0, 0};
    uint8_t tag_[16]{};
    uint64_t len_ct_ = 0;
};

} // anonymous namespace

// ═══════════════════════════════════════════════════════════════
//  Factory
// ═══════════════════════════════════════════════════════════════

std::unique_ptr<CipherCtx> create(
    Algorithm algo,
    Mode      mode,
    std::span<const uint8_t, 16> key,
    std::span<const uint8_t, 12> nonce)
{
    switch (mode) {
    case Mode::CTR:
        return std::make_unique<CtrCipherCtx>(key, nonce);
    case Mode::GCM:
        return std::make_unique<GcmCipherCtx>(key, nonce);
    case Mode::ECB:
        // ECB: manual one-block at a time
        return nullptr;
    default:
        return nullptr;
    }
}

} // namespace streamcipher::cipher
