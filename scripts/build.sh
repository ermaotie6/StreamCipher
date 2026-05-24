#!/bin/bash
# StreamCipher build script
set -euo pipefail

BUILD_DIR="${1:-build}"
BUILD_TYPE="${2:-Release}"

echo "=== StreamCipher Build ==="
echo "Build dir:  $BUILD_DIR"
echo "Build type: $BUILD_TYPE"
echo ""

cmake -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DSTREAMCIPHER_BUILD_TESTS=ON \
    -DSTREAMCIPHER_BUILD_BENCHMARKS=ON \
    -DSTREAMCIPHER_BUILD_EXAMPLES=ON \
    -DSTREAMCIPHER_BUILD_APPS=ON

cmake --build "$BUILD_DIR" -j"$(nproc)"

echo ""
echo "=== Build Complete ==="
echo ""
echo "Run tests:        ctest --test-dir $BUILD_DIR"
echo "Run benchmarks:   $BUILD_DIR/benchmarks/bench_aes"
echo "CLI tool:         $BUILD_DIR/apps/scipher --help"
