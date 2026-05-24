// Unit tests: Galois Field GF(2^8) operations
#include <catch2/catch_test_macros.hpp>
#include "streamcipher/core/gf.hpp"
#include <array>

using namespace streamcipher::gf;

TEST_CASE("GF(2^8) multiplication — identity and zero", "[gf]") {
    REQUIRE(mul(0x53, 0x01) == 0x53);
    REQUIRE(mul(0x00, 0x53) == 0x00);
    REQUIRE(mul(0x53, 0x00) == 0x00);
    REQUIRE(mul(0x01, 0xAB) == 0xAB);
}

TEST_CASE("GF(2^8) multiplication — commutativity", "[gf]") {
    for (uint8_t a = 0; a < 255; ++a) {
        for (uint8_t b = 0; b < 255; ++b) {
            REQUIRE(mul(a, b) == mul(b, a));
        }
    }
}

TEST_CASE("GF(2^8) multiplication — associativity", "[gf]") {
    // (a * b) * c == a * (b * c)
    for (uint8_t a : {0x02, 0x03, 0x53, 0x57, 0x83, 0xAB}) {
        for (uint8_t b : {0x04, 0x0A, 0x1F, 0x7C, 0x91, 0xCA}) {
            for (uint8_t c : {0x05, 0x0B, 0x2E, 0x6D, 0x88, 0xF1}) {
                REQUIRE(mul(mul(a, b), c) == mul(a, mul(b, c)));
            }
        }
    }
}

TEST_CASE("GF(2^8) multiplication — distributivity", "[gf]") {
    for (uint8_t a : {0x02, 0x53, 0xAB}) {
        for (uint8_t b : {0x04, 0x1F, 0xCA}) {
            for (uint8_t c : {0x05, 0x2E, 0xF1}) {
                REQUIRE(mul(a, b ^ c) == (mul(a, b) ^ mul(a, c)));
            }
        }
    }
}

TEST_CASE("GF(2^8) xtime", "[gf]") {
    REQUIRE(xtime(0x57) == mul(0x57, 0x02));
    REQUIRE(xtime(0x00) == 0x00);
    REQUIRE(xtime(0x80) == 0x1B);  // overflow case
    REQUIRE(xtime(0x01) == 0x02);
}

TEST_CASE("GF(2^8) xtime/mul consistency", "[gf]") {
    for (uint8_t a = 0; a < 255; ++a) {
        REQUIRE(xtime(a) == mul(a, 0x02));
    }
}

TEST_CASE("GF(2^8) inverse", "[gf]") {
    // a * inv(a) = 1 for a != 0
    for (uint8_t a = 1; a != 0; ++a) {
        REQUIRE(mul(a, inv(a)) == 0x01);
    }
    REQUIRE(inv(0x00) == 0x00);
    REQUIRE(inv(0x01) == 0x01);
}

TEST_CASE("GF(2^8) S-box — matches known AES S-box", "[gf]") {
    // Test a few known entries against the standard AES S-box
    REQUIRE(sbox(0x00) == 0x63);
    REQUIRE(sbox(0x01) == 0x7C);
    REQUIRE(sbox(0x53) == 0xED);
    REQUIRE(sbox(0xAB) == 0x62);
    REQUIRE(sbox(0xFF) == 0x16);
}

TEST_CASE("GF(2^8) S-box round-trip", "[gf]") {
    for (uint8_t a = 0; a != 0; ++a) {
        REQUIRE(inv_sbox(sbox(a)) == a);
    }
    REQUIRE(inv_sbox(sbox(0)) == 0);
}

TEST_CASE("GF(2^8) mul3/mul9/mul11/mul13/mul14", "[gf]") {
    for (uint8_t a = 0; a < 255; ++a) {
        REQUIRE(mul3(a)  == mul(a, 0x03));
        REQUIRE(mul9(a)  == mul(a, 0x09));
        REQUIRE(mul11(a) == mul(a, 0x0B));
        REQUIRE(mul13(a) == mul(a, 0x0D));
        REQUIRE(mul14(a) == mul(a, 0x0E));
    }
}

TEST_CASE("Batch multiplication", "[gf]") {
    std::array<GF8, 256> a, b, dst;
    for (int i = 0; i < 256; ++i) {
        a[i] = static_cast<uint8_t>(i);
        b[i] = static_cast<uint8_t>((i * 7 + 3) & 0xFF);
    }
    mul_batch(dst.data(), a.data(), b.data(), 256);
    for (int i = 0; i < 256; ++i) {
        REQUIRE(dst[i] == mul(a[i], b[i]));
    }
}

TEST_CASE("Batch S-box", "[gf]") {
    std::array<GF8, 256> src, dst;
    for (int i = 0; i < 256; ++i) src[i] = static_cast<uint8_t>(i);
    sbox_batch(dst.data(), src.data(), 256);
    for (int i = 0; i < 256; ++i) {
        REQUIRE(dst[i] == sbox(src[i]));
    }
}
