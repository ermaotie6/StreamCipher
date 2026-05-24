#!/bin/bash
# StreamCipher benchmark runner
set -euo pipefail

BUILD_DIR="${1:-build}"

BENCH_DIR="$BUILD_DIR/benchmarks"
if [ ! -d "$BENCH_DIR" ]; then
    echo "Benchmarks not built. Run scripts/build.sh first."
    exit 1
fi

echo "=== GF(2^8) Operations ==="
"$BENCH_DIR/bench_gf"

echo ""
echo "=== AES-128 Encryption ==="
"$BENCH_DIR/bench_aes"

echo ""
echo "=== Streaming Throughput ==="
"$BENCH_DIR/bench_stream"

echo ""
echo "=== CLI Benchmark ==="
"$BUILD_DIR/apps/scipher" benchmark
