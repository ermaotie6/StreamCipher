#pragma once
#include "streamcipher/core/parameters.hpp"
#include <span>

namespace streamcipher::detail {
// Fixed work for full tags; length is public. Not a whole-program timing proof.
inline bool verify_tag(std::span<const uint8_t> actual,
                       std::span<const uint8_t> expected) noexcept {
    if (actual.size() != cipher::TAG_SIZE || expected.size() != cipher::TAG_SIZE) return false;
    uint8_t difference = 0;
    for (size_t i = 0; i < cipher::TAG_SIZE; ++i) difference |= actual[i] ^ expected[i];
    return difference == 0;
}
}
