#pragma once
#include "streamcipher/memory/secure.hpp"
#include <cstddef>

namespace streamcipher::detail {
// Referenced storage must outlive the guard and must not move or resize.
class WipeGuard {
public:
    WipeGuard(void* storage, size_t size) noexcept
        : bytes_(static_cast<uint8_t*>(storage), size) {}
    ~WipeGuard() { memory::secure_zero(bytes_); }
    WipeGuard(const WipeGuard&) = delete;
    WipeGuard& operator=(const WipeGuard&) = delete;
private:
    std::span<uint8_t> bytes_;
};
}
