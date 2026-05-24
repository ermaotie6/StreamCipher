// Unit tests: SIMD abstraction layer
#include <catch2/catch_test_macros.hpp>
#include "streamcipher/simd/simd.hpp"
#include <cstring>

using namespace streamcipher::simd;

TEST_CASE("Vec128 XOR", "[simd]") {
    Vec128 a{}, b{}, expected{};
    for (int i = 0; i < 16; ++i) {
        a.data[i] = static_cast<uint8_t>(i);
        b.data[i] = static_cast<uint8_t>(i * 2);
        expected.data[i] = a.data[i] ^ b.data[i];
    }
    auto result = xor128(a, b);
    REQUIRE(std::memcmp(result.data, expected.data, 16) == 0);
}

TEST_CASE("Vec128 load/store round-trip", "[simd]") {
    uint8_t src[16];
    for (int i = 0; i < 16; ++i) src[i] = static_cast<uint8_t>(i * 7 + 3);

    auto v = load128(src);
    uint8_t dst[16]{};
    store128(dst, v);

    REQUIRE(std::memcmp(src, dst, 16) == 0);
}

TEST_CASE("Vec128 shift_bytes_left", "[simd]") {
    Vec128 a{};
    for (int i = 0; i < 16; ++i) a.data[i] = static_cast<uint8_t>(i);
    auto shifted = shift_bytes_left(a, 4);
    REQUIRE(shifted.data[0]  == 4);
    REQUIRE(shifted.data[12] == 0);
    REQUIRE(shifted.data[15] == 3);
}

TEST_CASE("CPU feature detection", "[simd]") {
    // These are compile-time checks; at runtime they reflect the build config.
    // Just verify they don't crash.
    REQUIRE_NOTHROW(has_sse41());
    REQUIRE_NOTHROW(has_avx2());
    REQUIRE_NOTHROW(has_aesni());
}
