#!/bin/bash
# Run from any directory; an optional build path is relative to the caller.
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="${1:-$SOURCE_DIR/build/local}"
BUILD_TYPE="${2:-Release}"
cmake -S "$SOURCE_DIR" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DSTREAMCIPHER_BUILD_TESTS=ON \
    -DSTREAMCIPHER_BUILD_BENCHMARKS=ON \
    -DSTREAMCIPHER_BUILD_EXAMPLES=ON \
    -DSTREAMCIPHER_BUILD_APPS=ON
cmake --build "$BUILD_DIR" --config "$BUILD_TYPE" --parallel
ctest --test-dir "$BUILD_DIR" -C "$BUILD_TYPE" --output-on-failure
