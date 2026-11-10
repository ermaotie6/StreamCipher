// Benchmark: GF(2^8) operations — comparison of scalar vs batch
#include <benchmark/benchmark.h>
#include "streamcipher/core/gf.hpp"

using namespace streamcipher::gf;

static void BM_GF_SingleMul(benchmark::State& state) {
    GF8 a = 0x53, b = 0xca;
    for (auto _ : state) {
        benchmark::DoNotOptimize(a);
        benchmark::DoNotOptimize(b);
        benchmark::DoNotOptimize(mul(a, b));
    }
}
BENCHMARK(BM_GF_SingleMul);

static void BM_GF_SingleInv(benchmark::State& state) {
    GF8 a = 0x53;
    for (auto _ : state) {
        benchmark::DoNotOptimize(a);
        benchmark::DoNotOptimize(inv(a));
    }
}
BENCHMARK(BM_GF_SingleInv);

static void BM_GF_BatchMul_1K(benchmark::State& state) {
    constexpr size_t N = 1024;
    GF8 a[N], b[N], dst[N];
    for (size_t i = 0; i < N; ++i) {
        a[i] = static_cast<uint8_t>(i);
        b[i] = static_cast<uint8_t>(i * 3 + 7);
    }
    for (auto _ : state) {
        mul_batch(dst, a, b, N);
        benchmark::DoNotOptimize(dst);
    }
}
BENCHMARK(BM_GF_BatchMul_1K);

static void BM_GF_BatchInv_1K(benchmark::State& state) {
    constexpr size_t N = 1024;
    GF8 src[N], dst[N];
    for (size_t i = 0; i < N; ++i) {
        src[i] = static_cast<uint8_t>(i); // Include all byte values, including zero.
    }
    for (auto _ : state) {
        inv_batch(dst, src, N);
        benchmark::DoNotOptimize(dst);
    }
}
BENCHMARK(BM_GF_BatchInv_1K);

BENCHMARK_MAIN();
