#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="${1:-$SOURCE_DIR/build/local}"
CONFIG="${2:-Release}"
for name in bench_gf bench_aes bench_stream; do
    executable="$BUILD_DIR/benchmarks/$name"
    if [[ ! -x "$executable" && ! -x "$executable.exe" ]]; then
        executable="$BUILD_DIR/benchmarks/$CONFIG/$name"
    fi
    if [[ -x "$executable.exe" ]]; then executable="$executable.exe"; fi
    if [[ ! -x "$executable" ]]; then
        echo "Missing benchmark executable: $executable" >&2
        exit 1
    fi
    "$executable"
done
