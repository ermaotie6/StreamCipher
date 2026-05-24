// Memory pool — slab allocator for fixed-size cipher blocks
//
// Pre-allocates a large contiguous region and hands out fixed-size slabs.
// Eliminates malloc/free overhead in the hot path and improves cache locality.

#pragma once

#include <cstdint>
#include <cstddef>
#include <cassert>
#include <new>

namespace streamcipher::memory {

// ── Fixed-Size Slab Pool ────────────────────────────────────

/// A simple slab allocator for fixed-size objects.
/// Allocates from a pre-allocated pool; never calls malloc/free individually.
template<size_t BlockSize, size_t BlockCount = 1024>
class SlabPool {
public:
    SlabPool();
    ~SlabPool();

    // Non-copyable, non-movable
    SlabPool(const SlabPool&) = delete;
    SlabPool& operator=(const SlabPool&) = delete;

    /// Allocate a block from the pool. Returns nullptr if pool is exhausted.
    [[nodiscard]] void* alloc() noexcept;

    /// Return a block to the pool.
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

    alignas(64) uint8_t pool_[BlockSize * BlockCount];  // Cache-line aligned
    Node*           free_list_;
    size_t          used_;
};

// ── Template Implementation ─────────────────────────────────

template<size_t BlockSize, size_t BlockCount>
SlabPool<BlockSize, BlockCount>::SlabPool()
    : free_list_(nullptr), used_(0)
{
    // Initialize free list
    for (size_t i = 0; i < BlockCount; ++i) {
        auto* node = reinterpret_cast<Node*>(&pool_[i * BlockSize]);
        node->next = free_list_;
        free_list_ = node;
    }
}

template<size_t BlockSize, size_t BlockCount>
SlabPool<BlockSize, BlockCount>::~SlabPool()
{
    // Static pool — nothing to free
}

template<size_t BlockSize, size_t BlockCount>
void* SlabPool<BlockSize, BlockCount>::alloc() noexcept
{
    if (!free_list_) return nullptr;
    auto* block = free_list_;
    free_list_ = free_list_->next;
    ++used_;
    return block;
}

template<size_t BlockSize, size_t BlockCount>
void SlabPool<BlockSize, BlockCount>::dealloc(void* ptr) noexcept
{
    if (!ptr) return;
    auto* node = static_cast<Node*>(ptr);
    node->next = free_list_;
    free_list_ = node;
    --used_;
}

// ── Type Aliases ─────────────────────────────────────────────

/// Pool for AES blocks (16 bytes each).
using AESBlockPool = SlabPool<16, 16384>;  // 256 KiB

/// Pool for cipher context work buffers (64 bytes each).
using CtxBufferPool = SlabPool<64, 4096>;   // 256 KiB

/// Pool for SIMD scratch buffers (32 bytes each).
using SIMDBufferPool = SlabPool<32, 8192>;  // 256 KiB

} // namespace streamcipher::memory
