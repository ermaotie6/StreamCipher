#include "streamcipher/core/bitslice.hpp"
#include <cstdio>
int main() {
    printf("SliceWord=%zu\n", sizeof(streamcipher::bitslice::SliceWord));
    printf("BitSliceState=%zu\n", sizeof(streamcipher::bitslice::BitSliceState));
    printf("SLICE_WIDTH=%zu\n", streamcipher::bitslice::SLICE_WIDTH);
    return 0;
}
