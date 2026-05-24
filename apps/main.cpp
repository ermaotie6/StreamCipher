// scipher — StreamCipher CLI tool
//
// Usage:
//   scipher encrypt <input> <output> [--mode ctr|gcm] [--key <hex>] [--nonce <hex>]
//   scipher decrypt <input> <output> [--mode ctr|gcm] [--key <hex>] [--nonce <hex>]
//   scipher benchmark [--size 1M] [--iterations 10]

#include "streamcipher/stream/pipeline.hpp"
#include <iostream>
#include <string>
#include <string_view>
#include <cstring>
#include <chrono>

using namespace streamcipher;

namespace {

void print_usage() {
    std::cout << R"(StreamCipher CLI — High-Performance Streaming Symmetric Encryption

Usage:
  scipher encrypt <input> <output> [options]
  scipher decrypt <input> <output> [options]
  scipher benchmark [options]
  scipher --help

Options:
  --mode  <ctr|gcm>   Cipher mode (default: ctr)
  --key   <hex>       32-hex-char key (default: built-in test key)
  --nonce <hex>       24-hex-char nonce (default: built-in test nonce)
  --size  <N>         Benchmark data size (default: 1M for 1 MiB)

Examples:
  scipher encrypt data.txt data.enc
  scipher decrypt data.enc data.txt
  scipher benchmark --size 10M
)";
}

bool parse_hex(std::string_view hex, uint8_t* out, size_t expected_len) {
    if (hex.size() != expected_len * 2) return false;
    for (size_t i = 0; i < expected_len; ++i) {
        auto hi = hex[i * 2];
        auto lo = hex[i * 2 + 1];
        auto val = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int h = val(hi), l = val(lo);
        if (h < 0 || l < 0) return false;
        out[i] = static_cast<uint8_t>((h << 4) | l);
    }
    return true;
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    std::string_view cmd = argv[1];

    if (cmd == "--help" || cmd == "-h") {
        print_usage();
        return 0;
    }

    if (cmd == "encrypt" || cmd == "decrypt") {
        if (argc < 4) {
            std::cerr << "Error: input and output files required.\n";
            return 1;
        }

        const char* in_file  = argv[2];
        const char* out_file = argv[3];

        // Default test key/nonce
        uint8_t key[16] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
        };
        uint8_t nonce[12] = {
            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
            0xf8, 0xf9, 0xfa, 0xfb
        };
        auto mode = cipher::Mode::CTR;

        // Parse options
        for (int i = 4; i < argc; ++i) {
            std::string_view arg = argv[i];
            if (arg == "--mode" && i + 1 < argc) {
                std::string_view m = argv[++i];
                if (m == "gcm") mode = cipher::Mode::GCM;
                else if (m == "ctr") mode = cipher::Mode::CTR;
                else { std::cerr << "Unknown mode: " << m << "\n"; return 1; }
            } else if (arg == "--key" && i + 1 < argc) {
                if (!parse_hex(argv[++i], key, 16)) {
                    std::cerr << "Invalid key hex.\n"; return 1;
                }
            } else if (arg == "--nonce" && i + 1 < argc) {
                if (!parse_hex(argv[++i], nonce, 12)) {
                    std::cerr << "Invalid nonce hex.\n"; return 1;
                }
            }
        }

        pipeline::FilePipeline pipe(
            cipher::Algorithm::AES_128, mode,
            std::span<const uint8_t, 16>(key),
            std::span<const uint8_t, 12>(nonce)
        );

        pipeline::PipelineConfig config;
        config.chunk_size = 1 << 20;
        config.on_progress = [](uint64_t done, uint64_t total) {
            if (total > 0) {
                std::cout << "\rProgress: " << (done * 100 / total) << "%" << std::flush;
            }
        };

        auto start = std::chrono::steady_clock::now();
        uint64_t bytes;

        if (cmd == "encrypt") {
            bytes = pipe.encrypt_file(in_file, out_file, config);
        } else {
            bytes = pipe.decrypt_file(in_file, out_file, config);
        }

        auto elapsed = std::chrono::steady_clock::now() - start;
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();

        std::cout << "\rDone. " << bytes << " bytes in " << ms << " ms";
        if (ms > 0) {
            double mbps = (bytes / (1024.0 * 1024.0)) / (ms / 1000.0);
            std::cout << " (" << mbps << " MiB/s)";
        }
        std::cout << "\n";

        return bytes > 0 ? 0 : 1;
    }

    if (cmd == "benchmark") {
        // Simple built-in benchmark (no external deps needed)
        constexpr size_t DATA_SIZE = 1 << 20;  // 1 MiB
        std::vector<uint8_t> data(DATA_SIZE);
        for (size_t i = 0; i < DATA_SIZE; ++i) data[i] = static_cast<uint8_t>(i);

        uint8_t key[16] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
        };
        uint8_t nonce[12] = {
            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
            0xf8, 0xf9, 0xfa, 0xfb
        };

        const int ITERATIONS = 10;

        std::cout << "Running CTR benchmark: " << (DATA_SIZE >> 20) << " MiB x " << ITERATIONS << " iterations\n";

        auto start = std::chrono::steady_clock::now();

        for (int i = 0; i < ITERATIONS; ++i) {
            std::vector<uint8_t> work = data;
            stream::encrypt_one_shot(
                cipher::Algorithm::AES_128, cipher::Mode::CTR,
                work, work,
                std::span<const uint8_t, 16>(key),
                std::span<const uint8_t, 12>(nonce)
            );
        }

        auto elapsed = std::chrono::steady_clock::now() - start;
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
        double total_mb = (DATA_SIZE * ITERATIONS) / (1024.0 * 1024.0);
        double mbps = total_mb / (ms / 1000.0);

        std::cout << "Total: " << total_mb << " MiB in " << ms << " ms\n";
        std::cout << "Throughput: " << mbps << " MiB/s\n";

        return 0;
    }

    std::cerr << "Unknown command: " << cmd << "\n";
    print_usage();
    return 1;
}
