// Example: Encrypt a file using CTR mode
#include "streamcipher/stream/pipeline.hpp"
#include <iostream>
#include <string>

using namespace streamcipher;

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <input> <output>\n";
        return 1;
    }

    // Fixed test key and nonce (in production, derive from password + KDF)
    constexpr uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    constexpr uint8_t nonce[12] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb
    };

    pipeline::FilePipeline pipe(
        cipher::Algorithm::AES_128,
        cipher::Mode::CTR,
        std::span<const uint8_t, 16>(key),
        std::span<const uint8_t, 12>(nonce)
    );

    pipeline::PipelineConfig config;
    config.chunk_size = 1 << 20;  // 1 MiB chunks
    config.on_progress = [](uint64_t done, uint64_t total) {
        if (total > 0) {
            int pct = static_cast<int>(done * 100 / total);
            std::cout << "\rEncrypting... " << pct << "%" << std::flush;
        }
    };

    auto bytes = pipe.encrypt_file(argv[1], argv[2], config);
    std::cout << "\rDone. " << bytes << " bytes written.\n";

    return bytes > 0 ? 0 : 1;
}
