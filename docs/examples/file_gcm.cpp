// Demonstration only: the fixed key/nonce below must not protect real data.
#include <streamcipher/streamcipher.hpp>
#include <array>
#include <cstdint>
#include <iostream>

int main(int argc, char* argv[]) try {
    if (argc != 4) {
        std::cerr << "Usage: file_gcm <input> <ciphertext> <recovered>\n";
        return 1;
    }
    std::cerr << "Demo uses a fixed test key and nonce. Use disposable input only.\n";
    namespace sc = streamcipher;
    const std::array<uint8_t, 16> key{};
    const std::array<uint8_t, 12> nonce{};
    sc::pipeline::FilePipeline pipe(
        sc::cipher::Algorithm::AES_128, sc::cipher::Mode::GCM, key, nonce);
    sc::pipeline::PipelineConfig config;
    config.chunk_size = 64 * 1024;
    config.on_progress = [](uint64_t done, uint64_t total) {
        if (total == 0) std::cout << "Empty payload\n";
        else std::cout << "\rPayload: " << done << '/' << total << std::flush;
    };
    const auto written = pipe.encrypt_file(argv[1], argv[2], config);
    std::cout << "\nEncrypted file: " << written << " bytes\n";
    const auto recovered = pipe.decrypt_file(argv[2], argv[3], config);
    std::cout << "\nAuthenticated plaintext: " << recovered << " bytes\n";
    return 0; // Empty output is a successful result too.
} catch (const std::exception& error) {
    std::cerr << "Error: " << error.what() << '\n';
    return 1;
}
