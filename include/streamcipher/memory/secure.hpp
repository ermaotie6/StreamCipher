#pragma once
#include <cstdint>
#include <span>

namespace streamcipher::memory {
// Overwrite this writable byte range using volatile stores. This does not erase
// caller-owned copies, registers, swap, snapshots or filesystem remnants.
void secure_zero(std::span<uint8_t> bytes) noexcept;
}
