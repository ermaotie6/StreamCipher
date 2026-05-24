#include "streamcipher/core/bitslice.hpp"
#include "streamcipher/core/aes.hpp"
#include "streamcipher/core/gf.hpp"
#include <cstdio>
#include <cstring>
using namespace streamcipher;

// Compare bit-sliced state (unpacked) against a reference byte array
bool check_unpacked(const bitslice::BitSliceState& state,
                    const uint8_t* ref, const char* label) {
    constexpr size_t B = bitslice::SLICE_WIDTH;
    uint8_t unpacked[B * 16];
    bitslice::unpack(state, std::span<uint8_t, B*16>(unpacked, B*16));
    for (size_t b = 0; b < B; b++) {
        for (int i = 0; i < 16; i++) {
            if (unpacked[b*16 + i] != ref[i]) {
                printf("%s: block %zu byte %d: got %02x expected %02x\n",
                       label, b, i, unpacked[b*16+i], ref[i]);
                return false;
            }
        }
    }
    printf("%s: all blocks match\n", label);
    return true;
}

int main() {
    constexpr size_t B = bitslice::SLICE_WIDTH;
    
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    
    uint8_t plaintext[16] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };
    
    auto rk = aes::expand_key(std::span<const uint8_t, 16>(key));
    
    // Make 8 identical blocks
    uint8_t blocks[B * 16];
    for (size_t b = 0; b < B; b++)
        std::memcpy(blocks + b*16, plaintext, 16);
    
    auto state = bitslice::pack(std::span<const uint8_t, B*16>(blocks, B*16));
    
    // Test AddRoundKey
    bitslice::add_round_key(state, rk[0]);
    
    // Scalar: apply AddRoundKey
    uint8_t scalar[16];
    std::memcpy(scalar, plaintext, 16);
    for (int i = 0; i < 16; i++) scalar[i] ^= rk[0][i];
    check_unpacked(state, scalar, "AddRoundKey[0]");
    
    // Test SubBytes
    bitslice::sub_bytes(state);
    for (int i = 0; i < 16; i++) scalar[i] = gf::sbox(scalar[i]);
    check_unpacked(state, scalar, "SubBytes");
    
    // Test ShiftRows
    bitslice::shift_rows(state);
    {
        uint8_t tmp[16];
        std::memcpy(tmp, scalar, 16);
        // Row 0: no change
        // Row 1: 1→5, 5→9, 9→13, 13→1
        uint8_t t = tmp[1]; tmp[1]=tmp[5]; tmp[5]=tmp[9]; tmp[9]=tmp[13]; tmp[13]=t;
        // Row 2: swap (2,10) and (6,14)
        std::swap(tmp[2], tmp[10]); std::swap(tmp[6], tmp[14]);
        // Row 3: left 3 = right 1
        t = tmp[15]; tmp[15]=tmp[11]; tmp[11]=tmp[7]; tmp[7]=tmp[3]; tmp[3]=t;
        std::memcpy(scalar, tmp, 16);
    }
    check_unpacked(state, scalar, "ShiftRows");
    
    return 0;
}
