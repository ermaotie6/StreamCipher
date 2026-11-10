#include <streamcipher/streamcipher.hpp>
#include <array>
#include <cstdint>
#include <iostream>
#include <span>
#include <stdexcept>
#include <vector>

int main() try {
    namespace sc = streamcipher;
    const std::array<uint8_t, 16> key{};
    const std::array<uint8_t, 12> nonce{};
    std::array<uint8_t, 16> block{};
    const auto original = block;
    const auto round_keys = sc::aes::expand_key(key);
    sc::aes::encrypt_block(block, round_keys);
    sc::aes::decrypt_block(block, round_keys);
    if (block != original) throw std::runtime_error("AES block mismatch");

    // Low-level CipherCtx uses separate input/output buffers and a detached tag.
    const std::array<uint8_t, 3> plain{1, 2, 3};
    std::array<uint8_t, 3> encrypted{}, candidate{};
    auto enc = sc::cipher::create(sc::cipher::Algorithm::AES_128,
        sc::cipher::Mode::GCM, key, nonce, true);
    enc->update(plain, encrypted);
    enc->finalize();
    auto dec = sc::cipher::create(sc::cipher::Algorithm::AES_128,
        sc::cipher::Mode::GCM, key, nonce, false);
    dec->update(encrypted, candidate);
    dec->finalize();
    if (!dec->verify_tag(enc->tag()) || candidate != plain)
        throw std::runtime_error("CipherCtx verification failed");

    // Packing changes representation only; it does not encrypt.
    std::array<uint8_t, sc::bitslice::SLICE_BYTES> blocks{}, unpacked{};
    blocks[3] = 0xa5;
    auto state = sc::bitslice::pack(blocks);
    sc::bitslice::unpack(state, unpacked);
    if (blocks != unpacked) throw std::runtime_error("Bit-slice mismatch");
    if (sc::gf::sbox(0x53) != 0xed) throw std::runtime_error("S-box mismatch");

    sc::memory::SlabPool<16, 4> pool;
    void* raw = pool.alloc();
    if (!raw) throw std::runtime_error("Pool exhausted");
    auto bytes = std::span<uint8_t>(static_cast<uint8_t*>(raw), 16);
    for (auto& byte : bytes) byte = 0;
    pool.dealloc(raw); // The returned memory must not be used afterwards.
    if (pool.used() != 0) throw std::runtime_error("Pool mismatch");

    std::vector<uint8_t> data(10);
    sc::memory::Chunker<uint8_t> chunks(std::span<uint8_t>(data), 4);
    size_t visited = 0;
    while (!chunks.done()) visited += chunks.next().size();
    if (visited != data.size()) throw std::runtime_error("Chunker mismatch");
    std::cout << "Core and memory examples passed. AES-NI usable by AES API: "
              << std::boolalpha << sc::aes::has_aesni() << '\n';
    return 0;
} catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
}
