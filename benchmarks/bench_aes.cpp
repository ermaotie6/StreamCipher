// Benchmark: AES-128 — scalar vs bit-sliced throughput
#include <benchmark/benchmark.h>
#include "streamcipher/core/aes.hpp"
#include "streamcipher/core/bitslice.hpp"
#include <cstring>
#include <vector>

using namespace streamcipher::aes;

static constexpr uint8_t KEY[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

// ── Key Expansion ───────────────────────────────────────────

static void BM_AES_KeyExpansion(benchmark::State& state) {
    auto key = std::span<const uint8_t, 16>(KEY);
    for (auto _ : state) {
        auto rk = expand_key(key);
        benchmark::DoNotOptimize(rk);
    }
}
BENCHMARK(BM_AES_KeyExpansion);

// ── Single Block (Scalar) ───────────────────────────────────

static void BM_AES_SingleEncrypt(benchmark::State& state) {
    uint8_t block[16] = {0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,
                         0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34};
    auto key = std::span<const uint8_t, 16>(KEY);
    for (auto _ : state) {
        encrypt_ecb(std::span<uint8_t, 16>(block), key);
        benchmark::DoNotOptimize(block);
    }
}
BENCHMARK(BM_AES_SingleEncrypt);

static void BM_AES_SingleDecrypt(benchmark::State& state) {
    uint8_t block[16] = {0x39,0x25,0x84,0x1d,0x02,0xdc,0x09,0xfb,
                         0xdc,0x11,0x85,0x97,0x19,0x6a,0x0b,0x32};
    auto key = std::span<const uint8_t, 16>(KEY);
    for (auto _ : state) {
        decrypt_ecb(std::span<uint8_t, 16>(block), key);
        benchmark::DoNotOptimize(block);
    }
}
BENCHMARK(BM_AES_SingleDecrypt);

// ── Bit-sliced Batch (8 blocks = 128 bytes) ────────────────

static void BM_AES_BitSliced_128B(benchmark::State& state) {
    constexpr size_t N = bitslice::SLICE_WIDTH;
    std::vector<uint8_t> blocks(N * 16);
    for (size_t i = 0; i < blocks.size(); ++i) blocks[i] = static_cast<uint8_t>(i);
    auto key = std::span<const uint8_t, 16>(KEY);

    for (auto _ : state) {
        encrypt_bitsliced(blocks.data(), N, key);
        benchmark::DoNotOptimize(blocks);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * N * 16);
}
BENCHMARK(BM_AES_BitSliced_128B);

// ── Scalar Batch (8 blocks) ────────────────────────────────

static void BM_AES_Scalar_128B(benchmark::State& state) {
    constexpr size_t N = bitslice::SLICE_WIDTH;
    std::vector<uint8_t> blocks(N * 16);
    for (size_t i = 0; i < blocks.size(); ++i) blocks[i] = static_cast<uint8_t>(i);
    auto rk = expand_key(std::span<const uint8_t, 16>(KEY));

    for (auto _ : state) {
        for (size_t b = 0; b < N; ++b) {
            encrypt_block(std::span<uint8_t, 16>(blocks.data() + b * 16, 16), rk);
        }
        benchmark::DoNotOptimize(blocks);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * N * 16);
}
BENCHMARK(BM_AES_Scalar_128B);

// ── Fast Path (64 KiB) ─────────────────────────────────────

static void BM_AES_Fast_64K(benchmark::State& state) {
    constexpr size_t N = 4096;  // 4096 blocks = 64 KiB
    std::vector<uint8_t> blocks(N * 16);
    for (size_t i = 0; i < blocks.size(); ++i) blocks[i] = static_cast<uint8_t>(i);
    auto key = std::span<const uint8_t, 16>(KEY);

    for (auto _ : state) {
        encrypt_fast(blocks.data(), N, key);
        benchmark::DoNotOptimize(blocks);
    }
    state.SetBytesProcessed(int64_t(state.iterations()) * N * 16);
}
BENCHMARK(BM_AES_Fast_64K);

BENCHMARK_MAIN();
