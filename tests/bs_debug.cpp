#include "streamcipher/core/bitslice.hpp"
#include "streamcipher/core/gf.hpp"
#include <cstdio>
#include <cstring>
using namespace streamcipher;

int main() {
    constexpr size_t B = bitslice::SLICE_WIDTH;
    uint8_t blocks[B * 16], recovered[B * 16];

    for (size_t i = 0; i < B * 16; i++) blocks[i] = static_cast<uint8_t>(i);

    auto state = bitslice::pack(
        std::span<const uint8_t, bitslice::SLICE_BYTES>(blocks, bitslice::SLICE_BYTES));
    bitslice::unpack(state,
        std::span<uint8_t, bitslice::SLICE_BYTES>(recovered, bitslice::SLICE_BYTES));

    printf("Pack/unpack: %s\n",
           memcmp(blocks, recovered, B*16) == 0 ? "OK" : "FAIL");
    if (memcmp(blocks, recovered, B*16) != 0) {
        for (size_t i = 0; i < 16; i++)
            printf("%02zx: %02x != %02x\n", i, blocks[i], recovered[i]);
    }
    return 0;
}
