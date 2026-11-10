// Fixed parameters are test fixtures. Use a secret key and a unique nonce in applications.
#include <streamcipher/streamcipher.hpp>
#include <array>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

int main() try {
    namespace sc = streamcipher;
    const std::array<uint8_t, 16> key{};
    const std::array<uint8_t, 12> nonce{};
    const std::string message = "Hello, StreamCipher!";
    const std::vector<uint8_t> plain(message.begin(), message.end());
    std::vector<uint8_t> encrypted(plain.size() + 16);

    const auto encrypted_size = sc::stream::encrypt_one_shot(
        sc::cipher::Algorithm::AES_128, sc::cipher::Mode::GCM,
        plain, encrypted, key, nonce);
    encrypted.resize(encrypted_size);

    std::vector<uint8_t> recovered(encrypted.size() - 16);
    const auto recovered_size = sc::stream::decrypt_one_shot(
        sc::cipher::Algorithm::AES_128, sc::cipher::Mode::GCM,
        encrypted, recovered, key, nonce);
    recovered.resize(recovered_size);
    if (recovered != plain) throw std::runtime_error("Round-trip mismatch");
    std::cout << std::string(recovered.begin(), recovered.end()) << '\n';

    // A bad tag must fail without modifying the caller's output buffer.
    encrypted.back() ^= 1;
    const auto before = recovered;
    bool rejected = false;
    try {
        sc::stream::decrypt_one_shot(
            sc::cipher::Algorithm::AES_128, sc::cipher::Mode::GCM,
            encrypted, recovered, key, nonce);
    } catch (const std::runtime_error&) {
        rejected = true;
    }
    if (!rejected || recovered != before)
        throw std::runtime_error("Authentication failure contract violated");
    std::cout << "Tampered tag rejected; output unchanged.\n";
    return 0;
} catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
}
