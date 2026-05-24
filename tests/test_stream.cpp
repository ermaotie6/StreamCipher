// Unit tests: Streaming CTR + GCM modes
#include <catch2/catch_test_macros.hpp>
#include "streamcipher/stream/stream.hpp"
#include <cstring>
#include <vector>

using namespace streamcipher::stream;

static constexpr uint8_t TEST_KEY[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};
static constexpr uint8_t TEST_NONCE[12] = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb
};

TEST_CASE("CTR stream — small buffer round-trip", "[stream]") {
    std::vector<uint8_t> data(256);
    for (size_t i = 0; i < data.size(); ++i) data[i] = static_cast<uint8_t>(i);
    auto orig = data;

    uint8_t buffer[512];
    auto n = encrypt_one_shot(streamcipher::cipher::Algorithm::AES_128,
                              streamcipher::cipher::Mode::CTR,
                              data, std::span<uint8_t>(buffer, sizeof(buffer)),
                              std::span<const uint8_t, 16>(TEST_KEY),
                              std::span<const uint8_t, 12>(TEST_NONCE));
    REQUIRE(n == data.size());

    // Encrypted data should differ from plaintext
    REQUIRE(std::memcmp(buffer, orig.data(), data.size()) != 0);

    uint8_t recovered[512];
    n = decrypt_one_shot(streamcipher::cipher::Algorithm::AES_128, streamcipher::cipher::Mode::CTR,
                         std::span<const uint8_t>(buffer, n),
                         std::span<uint8_t>(recovered, sizeof(recovered)),
                         std::span<const uint8_t, 16>(TEST_KEY),
                         std::span<const uint8_t, 12>(TEST_NONCE));
    REQUIRE(n == data.size());
    REQUIRE(std::memcmp(recovered, orig.data(), data.size()) == 0);
}

TEST_CASE("CTR stream — streaming API with multiple chunks", "[stream]") {
    auto proc = StreamProcessor::create(
        streamcipher::cipher::Algorithm::AES_128, streamcipher::cipher::Mode::CTR,
        std::span<const uint8_t, 16>(TEST_KEY),
        std::span<const uint8_t, 12>(TEST_NONCE),
        true);
    REQUIRE(proc != nullptr);

    std::vector<uint8_t> data(500);
    for (size_t i = 0; i < data.size(); ++i) data[i] = static_cast<uint8_t>(i * 3);
    auto orig = data;

    // Process in uneven chunks
    proc->process(std::span<uint8_t>(data.data(), 100));
    proc->process(std::span<uint8_t>(data.data() + 100, 200));
    proc->process(std::span<uint8_t>(data.data() + 300, 200));
    proc->finish();

    REQUIRE(proc->bytes_processed() == 500);

    // Encrypted data should differ
    REQUIRE(std::memcmp(data.data(), orig.data(), data.size()) != 0);

    // Decrypt
    auto dec = StreamProcessor::create(
        streamcipher::cipher::Algorithm::AES_128, streamcipher::cipher::Mode::CTR,
        std::span<const uint8_t, 16>(TEST_KEY),
        std::span<const uint8_t, 12>(TEST_NONCE),
        false);
    dec->process(data);
    dec->finish();

    REQUIRE(std::memcmp(data.data(), orig.data(), data.size()) == 0);
}

TEST_CASE("CTR stream — cross 16-byte boundary", "[stream]") {
    auto proc = StreamProcessor::create(
        streamcipher::cipher::Algorithm::AES_128, streamcipher::cipher::Mode::CTR,
        std::span<const uint8_t, 16>(TEST_KEY),
        std::span<const uint8_t, 12>(TEST_NONCE),
        true);

    // 31 bytes — crosses a block boundary
    std::vector<uint8_t> data(31);
    for (size_t i = 0; i < 31; ++i) data[i] = static_cast<uint8_t>(i + 5);
    auto orig = data;

    proc->process(data);
    proc->finish();

    REQUIRE(proc->bytes_processed() == 31);
    REQUIRE(std::memcmp(data.data(), orig.data(), 31) != 0);

    auto dec = StreamProcessor::create(
        streamcipher::cipher::Algorithm::AES_128, streamcipher::cipher::Mode::CTR,
        std::span<const uint8_t, 16>(TEST_KEY),
        std::span<const uint8_t, 12>(TEST_NONCE),
        false);
    dec->process(data);
    dec->finish();

    REQUIRE(std::memcmp(data.data(), orig.data(), 31) == 0);
}

TEST_CASE("GCM stream — encrypt/decrypt round-trip", "[stream][gcm]") {
    std::vector<uint8_t> data(256);
    for (size_t i = 0; i < data.size(); ++i) data[i] = static_cast<uint8_t>(i);
    auto orig = data;

    uint8_t buffer[512];
    auto n = encrypt_one_shot(streamcipher::cipher::Algorithm::AES_128, streamcipher::cipher::Mode::GCM,
                              data, std::span<uint8_t>(buffer, sizeof(buffer)),
                              std::span<const uint8_t, 16>(TEST_KEY),
                              std::span<const uint8_t, 12>(TEST_NONCE));
    // GCM adds 16-byte tag
    REQUIRE(n == data.size() + 16);

    // Encrypted data + tag should differ from plaintext
    REQUIRE(std::memcmp(buffer, orig.data(), data.size()) != 0);

    uint8_t recovered[512];
    n = decrypt_one_shot(streamcipher::cipher::Algorithm::AES_128, streamcipher::cipher::Mode::GCM,
                         std::span<const uint8_t>(buffer, n),
                         std::span<uint8_t>(recovered, sizeof(recovered)),
                         std::span<const uint8_t, 16>(TEST_KEY),
                         std::span<const uint8_t, 12>(TEST_NONCE));
    REQUIRE(n == data.size());
    REQUIRE(std::memcmp(recovered, orig.data(), data.size()) == 0);
}

TEST_CASE("GCM stream — streaming API", "[stream][gcm]") {
    auto proc = StreamProcessor::create(
        streamcipher::cipher::Algorithm::AES_128, streamcipher::cipher::Mode::GCM,
        std::span<const uint8_t, 16>(TEST_KEY),
        std::span<const uint8_t, 12>(TEST_NONCE),
        true);

    std::vector<uint8_t> data(500);
    for (size_t i = 0; i < data.size(); ++i) data[i] = static_cast<uint8_t>(i * 3);
    auto orig = data;

    proc->process(std::span<uint8_t>(data.data(), 200));
    proc->process(std::span<uint8_t>(data.data() + 200, 300));
    proc->finish();

    REQUIRE(proc->bytes_processed() == 500);
    auto tag = proc->tag();
    REQUIRE(tag.size() == 16);

    // Decrypt
    auto dec = StreamProcessor::create(
        streamcipher::cipher::Algorithm::AES_128, streamcipher::cipher::Mode::GCM,
        std::span<const uint8_t, 16>(TEST_KEY),
        std::span<const uint8_t, 12>(TEST_NONCE),
        false);
    dec->process(data);
    dec->finish();

    REQUIRE(std::memcmp(data.data(), orig.data(), data.size()) == 0);
}
