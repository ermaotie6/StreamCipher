// Memory pool — slab allocator for fixed-size cipher blocks
//
// Pre-allocates a large contiguous region and hands out fixed-size slabs.
// Eliminates malloc/free overhead in the hot path and improves cache locality.

#pragma once

#include <cstdint>
#include <cstddef>
#include <cassert>
#include <new>
#include <array>
#include <limits>

namespace streamcipher::memory {

// ── Fixed-Size Slab Pool ────────────────────────────────────

/// A simple slab allocator for fixed-size objects.
/// Allocates raw storage, not objects; callers construct/destroy their own objects.
/// Not thread-safe. Does not scrub contents; do not treat it as a secure allocator.
/// The pool must outlive every live allocation. Over-alignment is explicit.
template<size_t BlockSize, size_t BlockCount = 1024, size_t BlockAlignment = alignof(std::max_align_t)>
class SlabPool {
public:
    SlabPool();
    ~SlabPool();

    // Non-copyable, non-movable
    SlabPool(const SlabPool&) = delete;
    SlabPool& operator=(const SlabPool&) = delete;

    /// Allocate a block from the pool. Returns nullptr if pool is exhausted.
    [[nodiscard]] void* alloc() noexcept;

    /// Return a live block to the pool. Null/foreign/already freed pointers are ignored.
    void dealloc(void* ptr) noexcept;

    /// Total blocks in the pool.
    [[nodiscard]] constexpr size_t capacity() const noexcept { return BlockCount; }

    /// Blocks currently in use.
    [[nodiscard]] size_t used() const noexcept { return used_; }

private:
    // Free list node embedded in freed blocks
    struct Node {
        Node* next;
    };

    static_assert(BlockSize > 0 && BlockCount > 0);
    static_assert(BlockAlignment >= alignof(Node) && (BlockAlignment & (BlockAlignment - 1)) == 0,
                  "Block alignment must be a power of two and support a pointer");
    static constexpr size_t Alignment = BlockAlignment;
    static_assert(BlockSize <= (std::numeric_limits<size_t>::max)() - Alignment);
    static constexpr size_t MinSize = BlockSize < sizeof(Node) ? sizeof(Node) : BlockSize;
    static constexpr size_t Stride = (MinSize + Alignment - 1) / Alignment * Alignment;
    static_assert(BlockCount <= (std::numeric_limits<size_t>::max)() / Stride);
    alignas(Alignment > 64 ? Alignment : 64) uint8_t pool_[Stride * BlockCount];
    std::array<bool, BlockCount> allocated_{};
    Node*           free_list_;
    size_t          used_;
};

// ── Template Implementation ─────────────────────────────────

template<size_t BlockSize, size_t BlockCount, size_t BlockAlignment>
SlabPool<BlockSize, BlockCount, BlockAlignment>::SlabPool()
    : free_list_(nullptr), used_(0)
{
    // Initialize free list
    for (size_t i = 0; i < BlockCount; ++i) {
        auto* node = ::new (static_cast<void*>(&pool_[i * Stride])) Node{free_list_};
        free_list_ = node;
    }
}

template<size_t BlockSize, size_t BlockCount, size_t BlockAlignment>
SlabPool<BlockSize, BlockCount, BlockAlignment>::~SlabPool()
{
    // Static pool — nothing to free
}

template<size_t BlockSize, size_t BlockCount, size_t BlockAlignment>
void* SlabPool<BlockSize, BlockCount, BlockAlignment>::alloc() noexcept
{
    if (!free_list_) return nullptr;
    auto* block = free_list_;
    free_list_ = free_list_->next;
    allocated_[(reinterpret_cast<uintptr_t>(block) - reinterpret_cast<uintptr_t>(pool_)) / Stride] = true;
    ++used_;
    return block;
}

template<size_t BlockSize, size_t BlockCount, size_t BlockAlignment>
void SlabPool<BlockSize, BlockCount, BlockAlignment>::dealloc(void* ptr) noexcept
{
    if (!ptr) return;
    const auto address = reinterpret_cast<uintptr_t>(ptr);
    const auto start = reinterpret_cast<uintptr_t>(pool_);
    if (address < start || address - start >= sizeof(pool_) || (address - start) % Stride != 0) return;
    const auto index = (address - start) / Stride;
    if (!allocated_[index]) return;
    allocated_[index] = false;
    auto* node = ::new (ptr) Node{free_list_};
    free_list_ = node;
    --used_;
}

// ── Type Aliases ─────────────────────────────────────────────

/// Pool for AES blocks (16 bytes each).
using AESBlockPool = SlabPool<16, 16384>;  // 256 KiB

/// Pool for cipher context work buffers (64 bytes each).
using CtxBufferPool = SlabPool<64, 4096>;   // 256 KiB

/// Pool for SIMD scratch buffers (32 bytes each).
using SIMDBufferPool = SlabPool<32, 8192, 32>;  // 256 KiB

} // namespace streamcipher::memory
