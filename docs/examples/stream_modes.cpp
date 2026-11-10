// Fixed parameters are test fixtures, not a nonce management strategy.
#include <streamcipher/streamcipher.hpp>
#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <span>
#include <stdexcept>
#include <vector>

int main() try {
    namespace sc = streamcipher;
    const std::array<uint8_t, 16> key{};
    for (const auto mode : {sc::cipher::Mode::CTR, sc::cipher::Mode::GCM}) {
        std::array<uint8_t, 12> nonce{};
        nonce[0] = static_cast<uint8_t>(mode); // Separate fixtures for each mode.
        std::vector<uint8_t> plain(137);
        for (size_t i = 0; i < plain.size(); ++i) plain[i] = static_cast<uint8_t>(i);
        auto encrypted = plain;
        auto enc = sc::stream::StreamProcessor::create(
            sc::cipher::Algorithm::AES_128, mode, key, nonce, true);
        for (size_t offset = 0; offset < encrypted.size(); offset += 7) {
            enc->process(std::span<uint8_t>(encrypted).subspan(
                offset, std::min(size_t{7}, encrypted.size() - offset)));
        }
        enc->finish();
        // tag() is a borrowed view. Copy it if it must outlive enc.
        const std::vector<uint8_t> tag(enc->tag().begin(), enc->tag().end());

        auto candidate = encrypted;
        auto dec = sc::stream::StreamProcessor::create(
            sc::cipher::Algorithm::AES_128, mode, key, nonce, false);
        // Decryption chunk sizes can differ from encryption chunk sizes.
        for (size_t offset = 0; offset < candidate.size(); offset += 19) {
            dec->process(std::span<uint8_t>(candidate).subspan(
                offset, std::min(size_t{19}, candidate.size() - offset)));
        }
        dec->finish();
        if (mode == sc::cipher::Mode::GCM && !dec->verify_tag(tag))
            throw std::runtime_error("GCM authentication failed");
        // candidate must not be consumed before GCM verification above.
        if (candidate != plain) throw std::runtime_error("Round-trip mismatch");
        std::cout << (mode == sc::cipher::Mode::GCM ? "GCM" : "CTR")
                  << ": " << dec->bytes_processed() << " bytes recovered\n";
    }
    return 0;
} catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
}
