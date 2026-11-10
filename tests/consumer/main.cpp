#include <streamcipher/streamcipher.hpp>
#include <array>
#include <stdexcept>
int main() {
    namespace sc = streamcipher;
    std::array<uint8_t,16> key{}, encrypted{};
    std::array<uint8_t,12> nonce{};
    sc::stream::encrypt_one_shot(sc::cipher::Algorithm::AES_128, sc::cipher::Mode::GCM, {}, encrypted, key, nonce);
    if (sc::stream::decrypt_one_shot(sc::cipher::Algorithm::AES_128, sc::cipher::Mode::GCM,
                                   encrypted, {}, key, nonce) != 0)
        throw std::runtime_error("Consumer round trip failed");
    sc::simd::Vec256 wide{};
    return sc::simd::xor256(wide, wide).data[0];
}
