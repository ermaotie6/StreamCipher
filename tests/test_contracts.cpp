#include <catch2/catch_test_macros.hpp>
#include "streamcipher/core/cipher.hpp"
#include "streamcipher/stream/stream.hpp"
#include "streamcipher/stream/pipeline.hpp"
#include "streamcipher/memory/secure.hpp"
#include "streamcipher/memory/pool.hpp"
#include "streamcipher/simd/simd.hpp"
#include "../src/detail/wipe_guard.hpp"
#include <algorithm>
#include <array>
#include <limits>
#include <type_traits>

using namespace streamcipher;
namespace {
const std::array<uint8_t, 16> key{};
const std::array<uint8_t, 12> nonce{};
constexpr auto algo = cipher::Algorithm::AES_128;
}

TEST_CASE("Central mode contracts reject overflow without allocation", "[contracts]") {
    for (auto mode : {cipher::Mode::CTR, cipher::Mode::GCM}) {
        const auto spec = cipher::mode_spec(mode);
        for (auto size : {uint64_t{0}, uint64_t{17}, spec.max_payload}) {
            REQUIRE(cipher::encrypted_size(mode, size) == size + spec.tag_size);
            REQUIRE(cipher::decrypted_size(mode, size + spec.tag_size) == size);
        }
        REQUIRE_THROWS_AS(cipher::encrypted_size(mode, spec.max_payload + 1), std::length_error);
        REQUIRE_THROWS_AS(cipher::validate_length(mode, 1, (std::numeric_limits<uint64_t>::max)()), std::length_error);
    }
    REQUIRE_THROWS_AS(cipher::decrypted_size(cipher::Mode::GCM, 15), std::invalid_argument);
    REQUIRE_THROWS_AS(cipher::mode_spec(cipher::Mode::ECB), std::invalid_argument);
    REQUIRE_THROWS_AS(cipher::encrypted_size(static_cast<cipher::Mode>(255), 0), std::invalid_argument);
}

TEST_CASE("Direction overload preserves the legacy wire format", "[contracts]") {
    for (auto mode : {cipher::Mode::CTR, cipher::Mode::GCM}) {
        std::array<uint8_t, 33> legacy{}, typed{};
        auto a = cipher::create(algo, mode, key, nonce, true);
        auto b = cipher::create(algo, mode, key, nonce, cipher::Direction::Encrypt);
        a->update(legacy, legacy); b->update(typed, typed);
        a->finalize(); b->finalize();
        REQUIRE(legacy == typed);
        REQUIRE(std::equal(a->tag().begin(), a->tag().end(), b->tag().begin(), b->tag().end()));
        auto dec = stream::StreamProcessor::create(algo, mode, key, nonce, cipher::Direction::Decrypt);
        dec->process(typed); dec->finish();
        REQUIRE(std::all_of(typed.begin(), typed.end(), [](auto x) { return x == 0; }));
        if (mode == cipher::Mode::GCM) REQUIRE(dec->verify_tag(a->tag()));
    }
    REQUIRE_THROWS_AS(cipher::create(algo, cipher::Mode::CTR, key, nonce, static_cast<cipher::Direction>(42)), std::invalid_argument);
    REQUIRE_THROWS_AS(stream::StreamProcessor::create(algo, cipher::Mode::CTR, key, nonce, static_cast<cipher::Direction>(42)), std::invalid_argument);
}

TEST_CASE("Factories validate parameters at construction", "[contracts]") {
    REQUIRE_THROWS_AS(pipeline::FilePipeline(algo, cipher::Mode::ECB, key, nonce), std::invalid_argument);
    REQUIRE_THROWS_AS(pipeline::FilePipeline(static_cast<cipher::Algorithm>(42), cipher::Mode::CTR, key, nonce), std::invalid_argument);
    STATIC_REQUIRE_FALSE(std::is_copy_constructible_v<stream::StreamProcessor>);
    STATIC_REQUIRE_FALSE(std::is_copy_constructible_v<cipher::CipherCtx>);
}

TEST_CASE("Authentication failure has a typed backwards-compatible exception", "[contracts]") {
    STATIC_REQUIRE(std::is_base_of_v<std::runtime_error, cipher::AuthenticationError>);
    std::array<uint8_t, 16> encrypted{};
    std::array<uint8_t, 1> out{0x42};
    stream::encrypt_one_shot(algo, cipher::Mode::GCM, {}, encrypted, key, nonce);
    encrypted[0] ^= 1;
    REQUIRE_THROWS_AS(stream::decrypt_one_shot(algo, cipher::Mode::GCM, encrypted, out, key, nonce), cipher::AuthenticationError);
    REQUIRE(out[0] == 0x42);
}

TEST_CASE("Authentication lifecycle rejects early and short tags at both layers", "[contracts]") {
    auto ctx = cipher::create(algo, cipher::Mode::GCM, key, nonce);
    auto proc = stream::StreamProcessor::create(algo, cipher::Mode::GCM, key, nonce, true);
    std::array<uint8_t, 16> expected{};
    REQUIRE_FALSE(ctx->verify_tag(expected)); REQUIRE_FALSE(proc->verify_tag(expected));
    ctx->finalize(); proc->finish();
    REQUIRE(ctx->verify_tag(proc->tag())); REQUIRE(proc->verify_tag(ctx->tag()));
    REQUIRE_FALSE(ctx->verify_tag(proc->tag().first(15)));
    REQUIRE_FALSE(proc->verify_tag(ctx->tag().first(15)));
}

TEST_CASE("Secure cleanup handles empty buffers and exception unwinding", "[contracts]") {
    memory::secure_zero({});
    std::array<uint8_t, 37> bytes;
    bytes.fill(0xac);
    try {
        detail::WipeGuard wipe(bytes.data(), bytes.size());
        throw std::runtime_error("test");
    } catch (const std::runtime_error&) {}
    REQUIRE(std::all_of(bytes.begin(), bytes.end(), [](auto x) { return x == 0; }));
}

TEST_CASE("256-bit public API exists even in software-only builds", "[contracts]") {
    std::array<uint8_t, 32> a{}, b{}, out{};
    a.fill(0xa5); b.fill(0x5a);
    simd::store256(out.data(), simd::xor256(simd::load256(a.data()), simd::load256(b.data())));
    REQUIRE(std::all_of(out.begin(), out.end(), [](auto x) { return x == 0xff; }));
    REQUIRE(sizeof(simd::Vec256) == 32);
    REQUIRE(alignof(simd::Vec256) == 32);
}

TEST_CASE("Slab pools honor explicit over-alignment across every slot", "[contracts]") {
    memory::SlabPool<17, 3, 64> pool;
    std::array<void*, 3> blocks{};
    for (auto& block : blocks) {
        block = pool.alloc();
        REQUIRE(block != nullptr);
        REQUIRE(reinterpret_cast<uintptr_t>(block) % 64 == 0);
    }
    REQUIRE(pool.alloc() == nullptr);
    for (auto* block : blocks) pool.dealloc(block);
    REQUIRE(pool.used() == 0);
}
