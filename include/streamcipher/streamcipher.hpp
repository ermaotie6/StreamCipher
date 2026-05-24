// StreamCipher — High-Performance Streaming Symmetric Cipher Engine
// Umbrella header: include this to pull in all public APIs.

#pragma once

// Core — Galois Field & Bit-slicing
#include "streamcipher/core/gf.hpp"
#include "streamcipher/core/bitslice.hpp"
#include "streamcipher/core/aes.hpp"
#include "streamcipher/core/cipher.hpp"

// Stream — Pipeline & streaming framework
#include "streamcipher/stream/stream.hpp"
#include "streamcipher/stream/pipeline.hpp"

// SIMD — Hardware acceleration layer
#include "streamcipher/simd/simd.hpp"
#include "streamcipher/simd/aesni.hpp"

// Memory — Pool & span utilities
#include "streamcipher/memory/pool.hpp"
#include "streamcipher/memory/span_utils.hpp"
