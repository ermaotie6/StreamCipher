#include "streamcipher/memory/secure.hpp"

namespace streamcipher::memory {
void secure_zero(std::span<uint8_t> bytes) noexcept {
    volatile uint8_t* ptr = bytes.data();
    for (size_t i = 0; i < bytes.size(); ++i) ptr[i] = 0;
}
}
