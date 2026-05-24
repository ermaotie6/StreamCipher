// Benchmark: Streaming encryption throughput
#include <benchmark/benchmark.h>
#include "streamcipher/stream/stream.hpp"
#include <vector>

using namespace streamcipher::stream;

static constexpr uint8_t KEY[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};
static constexpr uint8_t NONCE[12] = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb
};

static void BM_CTR_Stream_1MiB(benchmark::State& state) {
    constexpr size_t SIZE = 1 << 20;  // 1 MiB
    std::vector<uint8_t> data(SIZE);
    for (size_t i = 0; i < SIZE; ++i) data[i] = static_cast<uint8_t>(i);

    for (auto _ : state) {
        auto proc = StreamProcessor::create(
            cipher::Algorithm::AES_128, cipher::Mode::CTR,
            std::span<const uint8_t, 16>(KEY),
            std::span<const uint8_t, 12>(NONCE), true);

        for (size_t off = 0; off < SIZE; off += 65536) {
            size_t chunk = std::min(size_t(65536), SIZE - off);
            proc->process(std::span<uint8_t>(data.data() + off, chunk));
        }
        proc->finish();
        benchmark::DoNotOptimize(data);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * SIZE);
}
BENCHMARK(BM_CTR_Stream_1MiB);

static void BM_CTR_OneShot_1MiB(benchmark::State& state) {
    constexpr size_t SIZE = 1 << 20;
    std::vector<uint8_t> plain(SIZE), cipher(SIZE);
    for (size_t i = 0; i < SIZE; ++i) plain[i] = static_cast<uint8_t>(i);

    for (auto _ : state) {
        encrypt_one_shot(cipher::Algorithm::AES_128, cipher::Mode::CTR,
                         plain, cipher,
                         std::span<const uint8_t, 16>(KEY),
                         std::span<const uint8_t, 12>(NONCE));
        benchmark::DoNotOptimize(cipher);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * SIZE);
}
BENCHMARK(BM_CTR_OneShot_1MiB);

static void BM_GCM_OneShot_1MiB(benchmark::State& state) {
    constexpr size_t SIZE = 1 << 20;
    std::vector<uint8_t> plain(SIZE), cipher(SIZE + 16);
    for (size_t i = 0; i < SIZE; ++i) plain[i] = static_cast<uint8_t>(i);

    for (auto _ : state) {
        encrypt_one_shot(cipher::Algorithm::AES_128, cipher::Mode::GCM,
                         plain, cipher,
                         std::span<const uint8_t, 16>(KEY),
                         std::span<const uint8_t, 12>(NONCE));
        benchmark::DoNotOptimize(cipher);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * SIZE);
}
BENCHMARK(BM_GCM_OneShot_1MiB);

BENCHMARK_MAIN();
