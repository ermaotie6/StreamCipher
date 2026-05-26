// cipher.cpp — CTR 和 GCM 两种工作模式
//
// CTR: 最简单的流密码模式，counter 递增 → AES 加密 → 密钥流 ⊕ 明文
// GCM: CTR 加密 + GHASH 认证（GF(2^128) 乘法），标准的 AEAD
//
// GHASH 的 GF(2^128) 乘法走的是移位加，常数时间。约简多项式是
// x^128 + x^7 + x^2 + x + 1，GCM 规范里的那个。

#include "streamcipher/core/cipher.hpp"
#include "streamcipher/core/gf.hpp"
#include <cstring>
#include <algorithm>

namespace streamcipher::cipher {

// ---- GHASH：GF(2^128) 上的哈希 ----

namespace {

struct GF128 { uint64_t hi, lo; };

// GF(2^128) 乘法，固定 128 次迭代，常数时间
// R = 0xE1 << 56 是约简多项式的低 64 位（GCM 的 bit-reflection 规定）
[[nodiscard]] GF128 gf128_mul(const GF128& a, const GF128& b) noexcept {
    GF128 result = {0, 0};
    uint64_t v_hi = a.hi, v_lo = a.lo;
    uint64_t z_hi = b.hi, z_lo = b.lo;

    for (int i = 0; i < 128; ++i) {
        uint64_t mask = -(z_lo & 1);      // 0 或 ~0，无分支条件 XOR
        result.lo ^= (v_lo & mask);
        result.hi ^= (v_hi & mask);

        z_lo = (z_lo >> 1) | (z_hi << 63);
        z_hi >>= 1;

        uint64_t carry = v_hi >> 63;
        v_hi = (v_hi << 1) | (v_lo >> 63);
        v_lo <<= 1;
        uint64_t reduce = -(carry & 1);
        v_lo ^= (0xE100000000000000ULL & reduce);
    }
    return result;
}

// 16 字节 big-endian → GF128
[[nodiscard]] GF128 bytes_to_gf128(const uint8_t* bytes) noexcept {
    GF128 r{};
    for (int i = 0; i < 8; ++i)  r.hi = (r.hi << 8) | bytes[i];
    for (int i = 8; i < 16; ++i) r.lo = (r.lo << 8) | bytes[i];
    return r;
}

// GF128 → 16 字节 big-endian
void gf128_to_bytes(const GF128& x, uint8_t* bytes) noexcept {
    uint64_t hi = x.hi, lo = x.lo;
    for (int i = 7; i >= 0; --i) { bytes[i] = hi & 0xFF; hi >>= 8; }
    for (int i = 15; i >= 8; --i) { bytes[i] = lo & 0xFF; lo >>= 8; }
}

} // anonymous namespace

// ---- CTR 模式实现 ----
// 注意：这里的 CTR 用简单的增量 counter（不是 NIST SP 800-38A 的 full counter block），
// 因为上层 StreamProcessor 已经从绝对字节位置算了 block_num，这里只是照办

namespace {

class CtrCipherCtx : public CipherCtx {
public:
    CtrCipherCtx(std::span<const uint8_t, 16> key,
                 std::span<const uint8_t, 12> nonce) {
        algo_ = Algorithm::AES_128;
        mode_ = Mode::CTR;
        std::memcpy(key_, key.data(), 16);
        // counter = nonce(12) || 0(4)
        std::memcpy(counter_, nonce.data(), 12);
        counter_[12] = counter_[13] = counter_[14] = counter_[15] = 0;
        round_keys_ = aes::expand_key(std::span<const uint8_t, 16>(key_, 16));
    }

    void update(std::span<const uint8_t> input,
                std::span<uint8_t> output) override {
        std::array<uint8_t, 16> keystream;
        size_t offset = 0;
        while (offset < input.size()) {
            std::memcpy(keystream.data(), counter_, 16);
            aes::encrypt_block(std::span<uint8_t, 16>(keystream), round_keys_);
            size_t chunk = std::min(size_t(16), input.size() - offset);
            for (size_t i = 0; i < chunk; ++i)
                output[offset + i] = input[offset + i] ^ keystream[i];
            offset += chunk;
            // 大端递增
            for (int i = 15; i >= 12; --i)
                if (++counter_[i] != 0) break;
        }
    }

    void finalize() override {}
    std::span<const uint8_t> tag() const override { return {}; }

private:
    alignas(64) uint8_t key_[16];
    alignas(64) uint8_t counter_[16];
    aes::RoundKeys round_keys_;
};

// ---- GCM 模式实现 ----
// 标准 GCM： H = AES_K(0), J0 = nonce||0^31||1
// GHASH 累加的是密文块（不是明文），最后 tag = GHASH ⊕ E_K(J0)
// 目前只支持 96-bit nonce，不支持其他长度的 nonce（规范里允许但麻烦）

class GcmCipherCtx : public CipherCtx {
public:
    GcmCipherCtx(std::span<const uint8_t, 16> key,
                 std::span<const uint8_t, 12> nonce) {
        algo_ = Algorithm::AES_128;
        mode_ = Mode::GCM;
        std::memcpy(key_, key.data(), 16);
        std::memcpy(nonce_, nonce.data(), 12);
        round_keys_ = aes::expand_key(std::span<const uint8_t, 16>(key_, 16));

        // H = E_K(0)
        std::memset(h_block_, 0, 16);
        aes::encrypt_block(std::span<uint8_t, 16>(h_block_), round_keys_);
        H_ = bytes_to_gf128(h_block_);

        // counter 从 1 开始（counter 0 是 J0 的位置）
        std::memcpy(counter_, nonce.data(), 12);
        counter_[12] = counter_[13] = counter_[14] = 0;
        counter_[15] = 1;

        // J0 = nonce || 0^31 || 1，预加密存着
        uint8_t j0[16];
        std::memcpy(j0, nonce.data(), 12);
        j0[12]=j0[13]=j0[14]=0; j0[15]=1;
        aes::encrypt_block(std::span<uint8_t, 16>(j0), round_keys_);
        j0_ = bytes_to_gf128(j0);
    }

    void update(std::span<const uint8_t> input,
                std::span<uint8_t> output) override {
        std::array<uint8_t, 16> keystream;
        std::array<uint8_t, 16> cipher_block;
        size_t offset = 0;

        while (offset < input.size()) {
            uint64_t abs_pos = len_ct_ + offset;
            size_t block_num = abs_pos / 16;
            size_t byte_in_block = abs_pos % 16;

            set_counter(block_num + 1);   // +1 因为 counter[0] 留给 J0 了

            std::memcpy(keystream.data(), counter_, 16);
            aes::encrypt_block(std::span<uint8_t, 16>(keystream), round_keys_);

            size_t chunk = std::min(size_t(16) - byte_in_block, input.size() - offset);
            for (size_t i = 0; i < chunk; ++i) {
                output[offset + i] = input[offset + i] ^ keystream[byte_in_block + i];
                cipher_block[i] = output[offset + i];
            }
            for (size_t i = chunk; i < 16; ++i) cipher_block[i] = 0;

            GF128 cb = bytes_to_gf128(cipher_block.data());
            auth_state_ = gf128_mul(xor128(auth_state_, cb), H_);
            offset += chunk;
        }
        len_ct_ += input.size();
    }

    void finalize() override {
        // 最后一块：len(A) || len(C)，各 64 位 big-endian，单位是 bit
        uint8_t len_block[16] = {0};
        uint64_t bits = len_ct_ * 8;
        for (int i = 15; i >= 8; --i) {
            len_block[i] = bits & 0xFF; bits >>= 8;
        }
        GF128 lb = bytes_to_gf128(len_block);
        auth_state_ = gf128_mul(xor128(auth_state_, lb), H_);

        GF128 tag_val = xor128(auth_state_, j0_);
        gf128_to_bytes(tag_val, tag_);
    }

    std::span<const uint8_t> tag() const override {
        return std::span<const uint8_t>(tag_, 16);
    }

private:
    static GF128 xor128(const GF128& a, const GF128& b) noexcept {
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

// ---- 工厂函数 ----

std::unique_ptr<CipherCtx> create(
    Algorithm algo, Mode mode,
    std::span<const uint8_t, 16> key,
    std::span<const uint8_t, 12> nonce)
{
    (void)algo;  // 目前只有 AES-128
    switch (mode) {
    case Mode::CTR: return std::make_unique<CtrCipherCtx>(key, nonce);
    case Mode::GCM: return std::make_unique<GcmCipherCtx>(key, nonce);
    default:        return nullptr;
    }
}

} // namespace streamcipher::cipher
