#include "options.hpp"
#include "streamcipher/stream/pipeline.hpp"
#include "streamcipher/stream/stream.hpp"
#include <algorithm>
#include <chrono>
#include <iostream>
#include <vector>

namespace streamcipher::cli {
void print_usage() {
    std::cout << R"(StreamCipher CLI — AES-128 CTR/GCM
Usage:
  scipher encrypt <input> <output> --key <hex> --nonce <hex> [options]
  scipher decrypt <input> <output> --key <hex> --nonce <hex> [options]
  scipher benchmark [--size 1M] [--iterations 10]
  scipher --help

File options:
  --mode <ctr|gcm>     Default ctr for compatibility; gcm adds authentication
  --key <hex>         32 hex characters (16-byte key)
  --nonce <hex>       24 hex characters; unique per encryption under a key
  --chunk-size <N>    Positive bytes with optional K/M/G suffix; default 1M
  --no-progress       Suppress progress messages on stderr

Each option may be supplied once. Sizes use powers of 1024.
Files contain raw ciphertext (CTR), or ciphertext followed by a 16-byte tag (GCM).
Save the mode and nonce separately. The benchmark uses fixed disposable test data.
)";
}
int execute(const Options& options) {
    using Clock = std::chrono::steady_clock;
    if (options.command == Command::Help) { print_usage(); return 0; }
    if (options.command == Command::Benchmark) {
        std::vector<uint8_t> data(static_cast<size_t>(options.size)), work(data.size());
        for (size_t i = 0; i < data.size(); ++i) data[i] = static_cast<uint8_t>(i);
        std::cout << "Running CTR benchmark: " << options.size << " bytes x " << options.iterations << " iterations\n";
        const auto start = Clock::now();
        for (uint64_t i = 0; i < options.iterations; ++i) {
            std::copy(data.begin(), data.end(), work.begin());
            stream::encrypt_one_shot(cipher::Algorithm::AES_128, cipher::Mode::CTR,
                                    work, work, options.key, options.nonce);
        }
        const auto elapsed = Clock::now() - start;
        const double seconds = std::chrono::duration<double>(elapsed).count();
        const double mib = double(options.size) * double(options.iterations) / (1024.0 * 1024.0);
        std::cout << "Total: " << mib << " MiB in "
                  << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() << " ms\n"
                  << "Throughput: " << (seconds > 0 ? mib / seconds : 0) << " MiB/s\n";
        return 0;
    }
    pipeline::FilePipeline pipe(cipher::Algorithm::AES_128, options.mode, options.key, options.nonce);
    pipeline::PipelineConfig config;
    config.chunk_size = options.chunk_size;
    if (options.progress) config.on_progress = [last = uint64_t{101}](uint64_t done, uint64_t total) mutable {
        const auto percent = total ? done * 100 / total : 100;
        if (percent != last) { std::cerr << "\rProgress: " << percent << "%" << std::flush; last = percent; }
    };
    const auto start = Clock::now();
    const auto bytes = options.command == Command::Encrypt
        ? pipe.encrypt_file(options.input, options.output, config)
        : pipe.decrypt_file(options.input, options.output, config);
    if (options.progress) std::cerr << '\n';
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start).count();
    std::cout << "Done. " << bytes << " bytes in " << ms << " ms\n";
    return 0;
}
}
