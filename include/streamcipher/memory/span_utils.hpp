// std::span utilities — zero-copy buffer handling
//
// Helper functions built on std::span to avoid unnecessary copies
// in the streaming pipeline.

#pragma once

#include <cstdint>
#include <cstddef>
#include <span>
#include <bit>

namespace streamcipher::memory {

// ── Alignment Helpers ───────────────────────────────────────

/// Check if a span starts at an aligned address.
template<typename T>
[[nodiscard]] constexpr bool is_aligned(std::span<T> s, size_t alignment) noexcept {
    return (reinterpret_cast<uintptr_t>(s.data()) % alignment) == 0;
}

/// Align a span's starting offset up to the next multiple of `alignment`.
/// Returns the number of bytes to skip.
template<typename T>
[[nodiscard]] constexpr size_t align_offset(std::span<T> s, size_t alignment) noexcept {
    auto addr = reinterpret_cast<uintptr_t>(s.data());
    auto misalignment = addr % alignment;
    return misalignment == 0 ? 0 : alignment - misalignment;
}

// ── Span Slicing ────────────────────────────────────────────

/// Split a span into two parts at `offset`.
template<typename T>
[[nodiscard]] constexpr std::pair<std::span<T>, std::span<T>>
split_at(std::span<T> s, size_t offset) noexcept {
    return {s.first(offset), s.subspan(offset)};
}

/// Take up to `n` elements from a span, returning the taken slice and the remainder.
template<typename T>
[[nodiscard]] constexpr std::pair<std::span<T>, std::span<T>>
take(std::span<T> s, size_t n) noexcept {
    n = std::min(n, s.size());
    return {s.first(n), s.subspan(n)};
}

/// Chunk a span into fixed-size pieces (last may be smaller).
template<typename T>
class Chunker {
public:
    explicit Chunker(std::span<T> data, size_t chunk_size)
        : data_(data), chunk_size_(chunk_size) {}

    /// Get the next chunk. Returns empty span when done.
    [[nodiscard]] std::span<T> next() noexcept {
        if (offset_ >= data_.size()) return {};
        size_t n = std::min(chunk_size_, data_.size() - offset_);
        auto chunk = data_.subspan(offset_, n);
        offset_ += n;
        return chunk;
    }

    /// Remaining data not yet chunked.
    [[nodiscard]] std::span<T> remaining() const noexcept {
        return data_.subspan(offset_);
    }

    [[nodiscard]] bool done() const noexcept { return offset_ >= data_.size(); }

private:
    std::span<T> data_;
    size_t chunk_size_;
    size_t offset_ = 0;
};

} // namespace streamcipher::memory
