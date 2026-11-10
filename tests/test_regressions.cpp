#include <catch2/catch_test_macros.hpp>
#include "streamcipher/core/aes.hpp"
#include "streamcipher/stream/stream.hpp"
#include "streamcipher/simd/aesni.hpp"
#include <algorithm>
#include <array>
#include <cstring>
#include <vector>
#include <random>
#include <limits>
#include <stdexcept>
#include "streamcipher/core/bitslice.hpp"
#include "streamcipher/memory/pool.hpp"
#include "streamcipher/memory/span_utils.hpp"

using namespace streamcipher;
namespace {
constexpr auto algo = cipher::Algorithm::AES_128;
const std::array<uint8_t, 16> key{};
const std::array<uint8_t, 12> nonce{};
}

TEST_CASE("GCM matches the zero-key known-answer vector", "[regression][gcm]") {
    const std::array<uint8_t, 32> expected{
        0x03,0x88,0xda,0xce,0x60,0xb6,0xa3,0x92,0xf3,0x28,0xc2,0xb9,0x71,0xb2,0xfe,0x78,
        0xab,0x6e,0x47,0xd4,0x2c,0xec,0x13,0xbd,0xf5,0x3a,0x67,0xb2,0x12,0x57,0xbd,0xdf};
    std::array<uint8_t, 16> plain{};
    std::array<uint8_t, 32> out{};
    REQUIRE(stream::encrypt_one_shot(algo, cipher::Mode::GCM, plain, out, key, nonce) == 32);
    REQUIRE(out == expected);
}

TEST_CASE("GCM rejects modified tags", "[regression][gcm]") {
    std::array<uint8_t, 16> plain{};
    std::array<uint8_t, 32> out{};
    stream::encrypt_one_shot(algo, cipher::Mode::GCM, plain, out, key, nonce);
    out.back() ^= 1;
    plain.fill(0xa5);
    const auto before = plain;
    REQUIRE_THROWS(stream::decrypt_one_shot(algo, cipher::Mode::GCM, out, plain, key, nonce));
    REQUIRE(plain == before);
}

TEST_CASE("GCM authentication is independent of chunk boundaries", "[regression][gcm]") {
    std::vector<uint8_t> a(35, 0x5a), b = a;
    auto one = stream::StreamProcessor::create(algo, cipher::Mode::GCM, key, nonce, true);
    auto split = stream::StreamProcessor::create(algo, cipher::Mode::GCM, key, nonce, true);
    one->process(a);
    for (auto& byte : b) split->process(std::span<uint8_t>(&byte, 1));
    one->finish(); split->finish();
    REQUIRE(a == b);
    REQUIRE(std::equal(one->tag().begin(), one->tag().end(), split->tag().begin()));
}

TEST_CASE("Low-level CTR preserves partial blocks across updates", "[regression][ctr]") {
    std::array<uint8_t, 35> plain{}, a{}, b{};
    auto one = cipher::create(algo, cipher::Mode::CTR, key, nonce);
    auto split = cipher::create(algo, cipher::Mode::CTR, key, nonce);
    one->update(plain, a);
    for (size_t i = 0; i < plain.size(); ++i)
        split->update(std::span<const uint8_t>(plain).subspan(i, 1), std::span<uint8_t>(b).subspan(i, 1));
    REQUIRE(a == b);
}

TEST_CASE("AES round fallback implements AES rather than XOR", "[regression][aesni]") {
    simd::Vec128 zero{};
    auto result = simd::aesni::enc_round(zero, zero);
    for (auto b : result.data) REQUIRE(b == 0x63);
}

TEST_CASE("Empty GCM message has the standard tag", "[gcm]") {
    const std::array<uint8_t, 16> expected{0x58,0xe2,0xfc,0xce,0xfa,0x7e,0x30,0x61,0x36,0x7f,0x1d,0x57,0xa4,0xe7,0x45,0x5a};
    std::array<uint8_t, 16> out{};
    REQUIRE(stream::encrypt_one_shot(algo, cipher::Mode::GCM, {}, out, key, nonce) == 16);
    REQUIRE(out == expected);
    REQUIRE(stream::decrypt_one_shot(algo, cipher::Mode::GCM, out, {}, key, nonce) == 0);
}

TEST_CASE("Cipher lifecycle and parameter validation", "[bounds]") {
    for (auto mode : {cipher::Mode::CTR, cipher::Mode::GCM}) {
        auto ctx = cipher::create(algo, mode, key, nonce);
        std::array<uint8_t, 4> data{};
        REQUIRE(ctx->tag().empty());
        REQUIRE_FALSE(ctx->verify_tag(key));
        REQUIRE_THROWS_AS(ctx->update(data, std::span<uint8_t>(data).first(3)), std::invalid_argument);
        REQUIRE_THROWS_AS(ctx->update(std::span<uint8_t>(data).first(3), std::span<uint8_t>(data).subspan(1)), std::invalid_argument);
        ctx->update(data, data);
        ctx->finalize();
        const std::vector<uint8_t> tag(ctx->tag().begin(), ctx->tag().end());
        ctx->finalize();
        REQUIRE(std::vector<uint8_t>(ctx->tag().begin(), ctx->tag().end()) == tag);
        REQUIRE_THROWS_AS(ctx->update({}, {}), std::logic_error);
        REQUIRE_FALSE(ctx->verify_tag({}));
    }
    REQUIRE_THROWS_AS(cipher::create(algo, cipher::Mode::ECB, key, nonce), std::invalid_argument);
    REQUIRE_THROWS_AS(cipher::create(static_cast<cipher::Algorithm>(255), cipher::Mode::CTR, key, nonce), std::invalid_argument);
    REQUIRE_THROWS_AS(stream::StreamProcessor::create(algo, static_cast<cipher::Mode>(255), key, nonce, true), std::invalid_argument);
}

TEST_CASE("Counter exhaustion checks exact boundaries without overflow", "[bounds]") {
    for (auto mode : {cipher::Mode::CTR, cipher::Mode::GCM}) {
        const auto max = mode == cipher::Mode::CTR ? cipher::CTR_MAX_BYTES : cipher::GCM_MAX_BYTES;
        REQUIRE_NOTHROW(cipher::validate_length(mode, max - 1, 1));
        REQUIRE_NOTHROW(cipher::validate_length(mode, max, 0));
        REQUIRE_THROWS_AS(cipher::validate_length(mode, max, 1), std::length_error);
        REQUIRE_THROWS_AS(cipher::validate_length(mode, max - 1, 2), std::length_error);
        REQUIRE_THROWS_AS(cipher::validate_length(mode, max + 1, 0), std::length_error);
        REQUIRE_THROWS_AS(cipher::validate_length(mode, 1, (std::numeric_limits<uint64_t>::max)()), std::length_error);
    }
}

TEST_CASE("One-shot rejects short buffers and truncated tags without writes", "[bounds]") {
    std::array<uint8_t, 32> data{};
    std::array<uint8_t, 31> out{};
    out.fill(0xa5);
    const auto before = out;
    for (auto mode : {cipher::Mode::CTR, cipher::Mode::GCM}) {
        REQUIRE_THROWS(stream::encrypt_one_shot(algo, mode, data, out, key, nonce));
        REQUIRE(out == before);
    }
    REQUIRE_THROWS(stream::decrypt_one_shot(algo, cipher::Mode::CTR, data, out, key, nonce));
    REQUIRE(out == before);
    for (size_t n = 0; n < 16; ++n) {
        REQUIRE_THROWS(stream::decrypt_one_shot(algo, cipher::Mode::GCM, std::span<const uint8_t>(data).first(n), out, key, nonce));
        REQUIRE(out == before);
    }
}

TEST_CASE("GCM rejects every tampered byte and wrong key or nonce", "[gcm]") {
    std::vector<uint8_t> plain(47, 0x5a), encrypted(63), recovered(47, 0xa5);
    stream::encrypt_one_shot(algo, cipher::Mode::GCM, plain, encrypted, key, nonce);
    const auto before = recovered;
    for (size_t i = 0; i < encrypted.size(); ++i) {
        auto changed = encrypted;
        changed[i] ^= 1;
        REQUIRE_THROWS(stream::decrypt_one_shot(algo, cipher::Mode::GCM, changed, recovered, key, nonce));
        REQUIRE(recovered == before);
        const auto saved = changed;
        REQUIRE_THROWS(stream::decrypt_one_shot(algo, cipher::Mode::GCM, changed, changed, key, nonce));
        REQUIRE(changed == saved);
    }
    auto bad_key = key; bad_key[0] = 1;
    auto bad_nonce = nonce; bad_nonce[0] = 1;
    REQUIRE_THROWS(stream::decrypt_one_shot(algo, cipher::Mode::GCM, encrypted, recovered, bad_key, nonce));
    REQUIRE_THROWS(stream::decrypt_one_shot(algo, cipher::Mode::GCM, encrypted, recovered, key, bad_nonce));
    REQUIRE(recovered == before);
}

TEST_CASE("All small chunk sizes agree for encryption and authenticated decryption", "[stream]") {
    for (auto mode : {cipher::Mode::CTR, cipher::Mode::GCM}) {
        std::vector<uint8_t> plain(131);
        for (size_t i = 0; i < plain.size(); ++i) plain[i] = static_cast<uint8_t>(i * 7);
        std::vector<uint8_t> expected(plain.size() + (mode == cipher::Mode::GCM ? 16 : 0));
        stream::encrypt_one_shot(algo, mode, plain, expected, key, nonce);
        for (size_t step = 1; step <= 33; ++step) {
            auto encrypted = plain;
            auto enc = stream::StreamProcessor::create(algo, mode, key, nonce, true);
            for (size_t i = 0; i < plain.size(); i += step) {
                enc->process({});
                enc->process(std::span<uint8_t>(encrypted).subspan(i, std::min(step, plain.size() - i)));
            }
            enc->finish();
            REQUIRE(std::equal(encrypted.begin(), encrypted.end(), expected.begin()));
            REQUIRE(enc->bytes_processed() == plain.size());
            if (mode == cipher::Mode::GCM) REQUIRE(enc->verify_tag(std::span<const uint8_t>(expected).last(16)));
            auto dec = stream::StreamProcessor::create(algo, mode, key, nonce, false);
            dec->process(encrypted);
            dec->finish();
            if (mode == cipher::Mode::GCM) REQUIRE(dec->verify_tag(enc->tag()));
            REQUIRE(encrypted == plain);
            REQUIRE_THROWS_AS(enc->process(encrypted), std::logic_error);
        }
    }
}

TEST_CASE("AES hardware software and bitslice paths agree on random blocks", "[aesni]") {
    std::mt19937 rng(20260919);
    for (size_t count : {size_t(0),size_t(1),size_t(7),size_t(8),size_t(9),size_t(17)}) {
        std::array<uint8_t, 16> random_key{};
        for (auto& x : random_key) x = static_cast<uint8_t>(rng());
        std::vector<uint8_t> plain(count * 16);
        for (auto& x : plain) x = static_cast<uint8_t>(rng());
        auto scalar = plain, hw = plain, bs = plain, fast = plain;
        auto rk = aes::expand_key(random_key);
        std::array<uint8_t, 176> hwkeys{};
        simd::aesni::expand_key_128(random_key, hwkeys);
        REQUIRE(std::memcmp(hwkeys.data(), rk.data(), 176) == 0);
        for (size_t i = 0; i < count; ++i) aes::encrypt_block(std::span<uint8_t,16>(scalar.data()+16*i,16), rk);
        simd::aesni::encrypt_blocks(hw.data(), count, hwkeys);
        aes::encrypt_bitsliced(bs.data(), count, random_key);
        aes::encrypt_fast(fast.data(), count, random_key);
        REQUIRE(hw == scalar); REQUIRE(bs == scalar); REQUIRE(fast == scalar);
        simd::aesni::decrypt_blocks(hw.data(), count, hwkeys);
        REQUIRE(hw == plain);
        for (size_t i = 0; i + 8 <= count; i += 8) {
            bitslice::decrypt_blocks(bs.data() + 16 * i, rk);
            REQUIRE(std::equal(bs.begin()+16*i, bs.begin()+16*(i+8), plain.begin()+16*i));
        }
    }
}

TEST_CASE("AES single rounds match the FIPS 197 intermediate states", "[aesni]") {
    const uint8_t initial[16]{0x00,0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80,0x90,0xa0,0xb0,0xc0,0xd0,0xe0,0xf0};
    const uint8_t roundkey[16]{0xd6,0xaa,0x74,0xfd,0xd2,0xaf,0x72,0xfa,0xda,0xa6,0x78,0xf1,0xd6,0xab,0x76,0xfe};
    const uint8_t expected[16]{0x89,0xd8,0x10,0xe8,0x85,0x5a,0xce,0x68,0x2d,0x18,0x43,0xd8,0xcb,0x12,0x8f,0xe4};
    auto encrypted = simd::aesni::enc_round(simd::load128(initial), simd::load128(roundkey));
    REQUIRE(std::memcmp(encrypted.data, expected, 16) == 0);
    // Exercise all four exported round functions against full scalar AES.
    std::array<uint8_t,16> k{};
    for (size_t i=0;i<16;++i) k[i]=static_cast<uint8_t>(i);
    auto rk = aes::expand_key(k);
    auto state = simd::load128(initial);
    for (size_t r=1;r<10;++r) state=simd::aesni::enc_round(state,simd::load128(rk[r].data()));
    state=simd::aesni::enc_round_last(state,simd::load128(rk[10].data()));
    auto reference = simd::load128(initial);
    for(size_t i=0;i<16;++i) reference.data[i]^=k[i];
    aes::encrypt_block(std::span<uint8_t,16>(reference.data),rk);
    REQUIRE(std::memcmp(state.data,reference.data,16)==0);
    state=simd::xor128(state,simd::load128(rk[10].data()));
    for(int r=9;r>0;--r) {
        std::array<uint8_t,128> repeated{};
        for(size_t i=0;i<8;++i) std::copy(rk[r].begin(),rk[r].end(),repeated.begin()+i*16);
        auto packed=bitslice::pack(repeated);
        bitslice::inv_mix_columns(packed);
        bitslice::unpack(packed,repeated);
        state=simd::aesni::dec_round(state,simd::load128(repeated.data()));
    }
    state=simd::aesni::dec_round_last(state,simd::load128(rk[0].data()));
    for(size_t i=0;i<16;++i) REQUIRE(state.data[i]==(initial[i]^k[i]));
}

TEST_CASE("Small slabs are aligned and invalid frees do not corrupt the pool", "[memory]") {
    memory::SlabPool<1, 3> pool;
    auto* a = pool.alloc(); auto* b = pool.alloc(); auto* c = pool.alloc();
    REQUIRE(a != b); REQUIRE(b != c); REQUIRE(a != c);
    REQUIRE(reinterpret_cast<uintptr_t>(a) % alignof(std::max_align_t) == 0);
    REQUIRE(pool.used() == 3); REQUIRE(pool.alloc() == nullptr);
    *static_cast<uint8_t*>(a) = 0xab;
    int foreign{};
    pool.dealloc(&foreign); pool.dealloc(static_cast<uint8_t*>(b)+1); pool.dealloc(nullptr);
    REQUIRE(pool.used() == 3);
    pool.dealloc(a); pool.dealloc(a);
    REQUIRE(pool.used() == 2); REQUIRE(pool.alloc() == a);
    pool.dealloc(a); pool.dealloc(b); pool.dealloc(c);
    REQUIRE(pool.used() == 0);
}

TEST_CASE("Span helpers reject invalid boundaries", "[memory]") {
    std::array<uint8_t, 7> data{};
    std::span<uint8_t> span(data);
    REQUIRE_FALSE(memory::is_aligned(span, 0));
    REQUIRE_THROWS_AS(memory::align_offset(span, 0), std::invalid_argument);
    REQUIRE_THROWS_AS(memory::split_at(span, 8), std::out_of_range);
    REQUIRE_THROWS_AS(memory::Chunker<uint8_t>(span, 0), std::invalid_argument);
    memory::Chunker<uint8_t> chunks(span, 3);
    REQUIRE(chunks.next().size() == 3); REQUIRE(chunks.next().size() == 3);
    REQUIRE(chunks.next().size() == 1); REQUIRE(chunks.done());
    REQUIRE(chunks.next().empty());
    REQUIRE(memory::take(span, 999).first.size() == span.size());
}

// NIST AES_GCM.pdf, GCM-AES128 Example #2 (AADlen=0, PTlen=512).
TEST_CASE("NIST GCM multi-block known-answer vector", "[gcm]") {
    const std::array<uint8_t, 16> k{0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08};
    const std::array<uint8_t, 12> iv{0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,0xde,0xca,0xf8,0x88};
    const std::array<uint8_t, 64> plain{0xd9,0x31,0x32,0x25,0xf8,0x84,0x06,0xe5,0xa5,0x59,0x09,0xc5,0xaf,0xf5,0x26,0x9a,0x86,0xa7,0xa9,0x53,0x15,0x34,0xf7,0xda,0x2e,0x4c,0x30,0x3d,0x8a,0x31,0x8a,0x72,0x1c,0x3c,0x0c,0x95,0x95,0x68,0x09,0x53,0x2f,0xcf,0x0e,0x24,0x49,0xa6,0xb5,0x25,0xb1,0x6a,0xed,0xf5,0xaa,0x0d,0xe6,0x57,0xba,0x63,0x7b,0x39,0x1a,0xaf,0xd2,0x55};
    const std::array<uint8_t, 80> expected{0x42,0x83,0x1e,0xc2,0x21,0x77,0x74,0x24,0x4b,0x72,0x21,0xb7,0x84,0xd0,0xd4,0x9c,0xe3,0xaa,0x21,0x2f,0x2c,0x02,0xa4,0xe0,0x35,0xc1,0x7e,0x23,0x29,0xac,0xa1,0x2e,0x21,0xd5,0x14,0xb2,0x54,0x66,0x93,0x1c,0x7d,0x8f,0x6a,0x5a,0xac,0x84,0xaa,0x05,0x1b,0xa3,0x0b,0x39,0x6a,0x0a,0xac,0x97,0x3d,0x58,0xe0,0x91,0x47,0x3f,0x59,0x85,0x4d,0x5c,0x2a,0xf3,0x27,0xcd,0x64,0xa6,0x2c,0xf3,0x5a,0xbd,0x2b,0xa6,0xfa,0xb4};
    std::array<uint8_t,80> out{};
    REQUIRE(stream::encrypt_one_shot(algo,cipher::Mode::GCM,plain,out,k,iv)==out.size());
    REQUIRE(out==expected);
    std::array<uint8_t,64> recovered{};
    REQUIRE(stream::decrypt_one_shot(algo,cipher::Mode::GCM,expected,recovered,k,iv)==plain.size());
    REQUIRE(recovered==plain);
}

TEST_CASE("One-shot supports exact and partial buffer overlap", "[bounds]") {
    const std::vector<uint8_t> plain(47,0x5a);
    for(auto mode:{cipher::Mode::CTR,cipher::Mode::GCM}) {
        std::vector<uint8_t> expected(plain.size()+(mode==cipher::Mode::GCM?16:0));
        stream::encrypt_one_shot(algo,mode,plain,expected,key,nonce);
        for(size_t offset:{size_t(0),size_t(1),size_t(5)}) {
            std::vector<uint8_t> buffer(expected.size()+offset);
            std::copy(plain.begin(),plain.end(),buffer.begin());
            auto output=std::span<uint8_t>(buffer).subspan(offset);
            REQUIRE(stream::encrypt_one_shot(algo,mode,std::span<const uint8_t>(buffer).first(plain.size()),output,key,nonce)==expected.size());
            REQUIRE(std::equal(expected.begin(),expected.end(),output.begin()));
            REQUIRE(stream::decrypt_one_shot(algo,mode,output,buffer,key,nonce)==plain.size());
            REQUIRE(std::equal(plain.begin(),plain.end(),buffer.begin()));
        }
    }
}
