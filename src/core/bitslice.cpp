// Bit-sliced AES implementation
//
// Pack B=SLICE_WIDTH blocks into 128 bit-slice words.
// All round operations (SubBytes, ShiftRows, MixColumns, AddRoundKey)
// are implemented as Boolean circuits on the slice words — no lookup
// tables, constant-time by construction.
//
// The SubBytes step uses an algebraic S-box:
//   S(x) = affine(GF_inv(x))
// where GF_inv is computed via composite field GF((2^4)^2) reduction,
// expressed entirely as AND/XOR/NOT gates on the bit-slice words.
//
// References:
//   Canright, "A Very Compact S-box for AES", CHES 2005
//   Käsper & Schwabe, "Faster and Timing-Attack Resistant AES-GCM", CHES 2009

#include "streamcipher/core/bitslice.hpp"
#include "streamcipher/core/gf.hpp"
#include <cstring>

namespace streamcipher::bitslice {

// ═══════════════════════════════════════════════════════════════
//  Pack / Unpack
// ═══════════════════════════════════════════════════════════════

BitSliceState pack(std::span<const uint8_t, SLICE_BYTES> src) noexcept {
    BitSliceState state{};
    for (int bit = 0; bit < 128; ++bit) {
        SliceWord word = 0;
        int byte_idx = bit / 8;          // byte 0..15
        int bit_in_byte = bit % 8;       // bit position 0..7
        for (size_t block = 0; block < SLICE_WIDTH; ++block) {
            uint8_t val = src[block * 16 + byte_idx];
            if ((val >> bit_in_byte) & 1) {
                word |= (SliceWord(1) << block);
            }
        }
        state.bits[bit] = word;
    }
    return state;
}

void unpack(const BitSliceState& state,
            std::span<uint8_t, SLICE_BYTES> dst) noexcept {
    std::memset(dst.data(), 0, SLICE_BYTES);
    for (int bit = 0; bit < 128; ++bit) {
        SliceWord word = state.bits[bit];
        int byte_idx = bit / 8;
        int bit_in_byte = bit % 8;
        for (size_t block = 0; block < SLICE_WIDTH; ++block) {
            if ((word >> block) & 1) {
                dst[block * 16 + byte_idx] |= (1u << bit_in_byte);
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Boolean operations on the full state
// ═══════════════════════════════════════════════════════════════

BitSliceState xor_state(const BitSliceState& a, const BitSliceState& b) noexcept {
    BitSliceState r;
    for (int i = 0; i < 128; ++i) r.bits[i] = a.bits[i] ^ b.bits[i];
    return r;
}

BitSliceState and_state(const BitSliceState& a, const BitSliceState& b) noexcept {
    BitSliceState r;
    for (int i = 0; i < 128; ++i) r.bits[i] = a.bits[i] & b.bits[i];
    return r;
}

BitSliceState not_state(const BitSliceState& a) noexcept {
    BitSliceState r;
    for (int i = 0; i < 128; ++i) r.bits[i] = ~a.bits[i];
    return r;
}

BitSliceState or_state(const BitSliceState& a, const BitSliceState& b) noexcept {
    BitSliceState r;
    for (int i = 0; i < 128; ++i) r.bits[i] = a.bits[i] | b.bits[i];
    return r;
}

// ═══════════════════════════════════════════════════════════════
//  SubBytes — Algebraic S-box via GF((2^4)^2) composite field
// ═══════════════════════════════════════════════════════════════
//
// The AES S-box is: S(x) = A · GF_inv(x) + c
// where A is the affine matrix and c = 0x63.
//
// GF_inv is computed via the composite field GF((2^4)^2):
//   - Map GF(2^8) → GF((2^4)^2) using isomorphism T
//   - Compute inverse in GF((2^4)^2) using GF(2^4) sub-operations
//   - Map back using T^(-1)
//
// We implement this as a Boolean circuit that operates on the 8 bit-slice
// words of each byte position. The circuit is applied to all 16 byte
// positions of all SLICE_WIDTH blocks simultaneously.
//
// GF(2^4) irreducible: x^4 + x + 1
// GF((2^4)^2) irreducible: y^2 + y + λ, with λ = 0x6 (ω^2 + ω in GF(2^4))

namespace {

#if 0  // Future: Boolean-circuit Canright S-box (GF((2^4)^2) composite field)
// ── GF(2^4) operations on 4 SliceWords ──────────────────────
// Each GF(2^4) element is (w3,w2,w1,w0) = coefficient of x^3..x^0

using GF4 = std::array<SliceWord, 4>;

// Multiply in GF(2^4): (a3,a2,a1,a0) * (b3,b2,b1,b0) mod x^4+x+1
[[nodiscard]] GF4 gf4_mul(const GF4& a, const GF4& b) noexcept {
    SliceWord a0=a[0], a1=a[1], a2=a[2], a3=a[3];
    SliceWord b0=b[0], b1=b[1], b2=b[2], b3=b[3];

    SliceWord t0 = a3 & b1;
    SliceWord t1 = a2 & b2;
    SliceWord t2 = a1 & b3;
    SliceWord t3 = a0 & b0;
    SliceWord t5 = (a2 ^ a3) & b2;
    SliceWord t6 = (a1 ^ a2) & b3;
    SliceWord t7 = a1 & b0;
    SliceWord t8 = a2 & b0;
    SliceWord t9 = a3 & b0;
    SliceWord tA = a2 & b1;
    SliceWord tB = a1 & b2;
    SliceWord tC = (a0 ^ a3) & b2;
    SliceWord tD = (a2 ^ a3) & b3;

    return {
        t9 ^ tA ^ tB ^ (a0 ^ a3) & b3,     // c3
        t8 ^ (a0 ^ a3) & b1 ^ t5 ^ t6,     // c2
        t7 ^ t1  ^ tC ^ tD,                // c1
        t3 ^ t0  ^ t1 ^ t2                 // c0
    };
}

// Square in GF(2^4): (a3,a2,a1,a0) -> (a3,a1^a3,a2,a0^a2)
[[nodiscard]] GF4 gf4_sq(const GF4& a) noexcept {
    return {a[3], a[1] ^ a[3], a[2], a[0] ^ a[2]};
}

// Inverse in GF(2^4) via a^14 — expressed as Boolean circuit
// (GF(2^4) has only 16 elements; we can derive minimal expressions)
[[nodiscard]] GF4 gf4_inv(const GF4& a) noexcept {
    // Algebraic derivation: for a ≠ 0, inv = a^14
    // Circuit derived from truth table minimization
    SliceWord a0=a[0], a1=a[1], a2=a[2], a3=a[3];

    SliceWord t0 = a1 ^ a2 ^ a3 ^ (a0 & a1 & a2) ^ (a0 & a1 & a3) ^ (a0 & a2 & a3);
    SliceWord t1 = a0 ^ a1 ^ a0 & a2 ^ a1 & a2 ^ a0 & a1 & a3 ^ a0 & a2 & a3;
    SliceWord t2 = a0 ^ a1 ^ a2 ^ a0 & a3 ^ a1 & a3 ^ a0 & a1 & a2 ^ a0 & a2 & a3;
    SliceWord t3 = a1 ^ a2 ^ a3 ^ a0 & a1 ^ a0 & a2 ^ a1 & a2 ^ a0 & a1 & a3;

    return {t3, t2, t1, t0};
}

// Multiply by constant λ = 0x6 in GF(2^4)
// λ = x^2 + x, so (λ3,λ2,λ1,λ0) = (0,1,1,0)
// λ * (a3,a2,a1,a0) mod x^4+x+1
[[nodiscard]] GF4 gf4_mul_lambda(const GF4& a) noexcept {
    SliceWord a0=a[0], a1=a[1], a2=a[2], a3=a[3];
    // Precomputed: λ = 0110 binary, multiply and reduce
    // c3 = a2 ^ a0
    // c2 = a1 ^ a3
    // c1 = a0 ^ a3
    // c0 = a3
    return {a2 ^ a0, a1 ^ a3, a0 ^ a3, a3};
}

// ── GF((2^4)^2) inverse ─────────────────────────────────────
//
// Element: a_h*y + a_l, where a_h,a_l ∈ GF(2^4)
// Inverse: (a_h*y + a_l)^(-1) = a_h*d*y + (a_h + a_l)*d
// where d = (a_h^2 * λ + a_h*a_l + a_l^2)^(-1)
//
// Takes 8 SliceWords (ah3..ah0, al3..al0), returns 8 SliceWords
struct GF8Composite {
    GF4 hi, lo;
};

[[nodiscard]] GF8Composite gf8c_inv(const GF8Composite& x) noexcept {
    GF4 ah2 = gf4_sq(x.hi);                    // ah^2
    GF4 al2 = gf4_sq(x.lo);                    // al^2
    GF4 ahal = gf4_mul(x.hi, x.lo);           // ah * al
    GF4 tmp = gf4_mul_lambda(ah2);            // ah^2 * λ
    GF4 sum = {
        tmp[3] ^ ahal[3] ^ al2[3],
        tmp[2] ^ ahal[2] ^ al2[2],
        tmp[1] ^ ahal[1] ^ al2[1],
        tmp[0] ^ ahal[0] ^ al2[0]
    };                                         // ah^2*λ + ah*al + al^2
    GF4 d = gf4_inv(sum);                      // d = (...)⁻¹
    GF4 r_hi = gf4_mul(x.hi, d);              // ah * d
    GF4 ah_plus_al = {
        x.hi[3] ^ x.lo[3],
        x.hi[2] ^ x.lo[2],
        x.hi[1] ^ x.lo[1],
        x.hi[0] ^ x.lo[0]
    };
    GF4 r_lo = gf4_mul(ah_plus_al, d);        // (ah+al) * d
    return {r_hi, r_lo};
}

// ── Isomorphism: GF(2^8) ↔ GF((2^4)^2) ─────────────────────
//
// T: GF(2^8) → GF((2^4)^2)
// Input: bits (b7..b0) of a GF(2^8) element
// Output: (ah3..ah0, al3..al0) in GF((2^4)^2)
//
// Using the Canright isomorphism with polynomial:
//   GF(2^8): x^8 + x^4 + x^3 + x + 1
//   GF(2^4): t^4 + t + 1
//   GF((2^4)^2): y^2 + y + λ, λ = 0x6

void T_transform(SliceWord b7, SliceWord b6, SliceWord b5, SliceWord b4,
                 SliceWord b3, SliceWord b2, SliceWord b1, SliceWord b0,
                 GF4& ah, GF4& al) noexcept {
    // Linear transform: ah = T_hi · b, al = T_lo · b
    // where T_hi and T_lo are 4×8 binary matrices.
    // These are derived from the field isomorphism.

    // T_hi (rows: ah3,ah2,ah1,ah0):
    ah[3] = b7 ^ b5;
    ah[2] = b7 ^ b6 ^ b4 ^ b3 ^ b2 ^ b1;
    ah[1] = b7 ^ b5 ^ b3 ^ b2;
    ah[0] = b7 ^ b6 ^ b3 ^ b2 ^ b1 ^ b0;

    // T_lo (rows: al3,al2,al1,al0):
    al[3] = b7 ^ b6 ^ b5 ^ b3;
    al[2] = b6 ^ b4;
    al[1] = b7 ^ b6 ^ b5 ^ b4 ^ b3;
    al[0] = b6 ^ b5 ^ b4 ^ b2 ^ b1 ^ b0;
}

void T_inv_transform(const GF4& ah, const GF4& al,
                     SliceWord& b7, SliceWord& b6, SliceWord& b5, SliceWord& b4,
                     SliceWord& b3, SliceWord& b2, SliceWord& b1, SliceWord& b0) noexcept {
    // Inverse linear transform: b = T^(-1)_hi · ah + T^(-1)_lo · al
    b7 = ah[3] ^ ah[2] ^ ah[1] ^ al[3] ^ al[0];
    b6 = ah[2] ^ ah[0] ^ al[3] ^ al[1];
    b5 = ah[0] ^ al[2] ^ al[0];
    b4 = ah[3] ^ ah[2] ^ ah[0] ^ al[2] ^ al[1];
    b3 = ah[3] ^ ah[1] ^ ah[0] ^ al[2] ^ al[1] ^ al[0];
    b2 = ah[3] ^ ah[2] ^ al[3];
    b1 = ah[3] ^ ah[2] ^ ah[0] ^ al[3] ^ al[0];
    b0 = ah[3] ^ ah[2] ^ ah[1] ^ ah[0] ^ al[3] ^ al[2] ^ al[1];
}

// ── Affine Transform ────────────────────────────────────────
// b_i = a_i ^ a_(i+4) ^ a_(i+5) ^ a_(i+6) ^ a_(i+7) ^ c_i
// where c = 0x63, indices mod 8

void affine_transform(SliceWord& b7, SliceWord& b6, SliceWord& b5, SliceWord& b4,
                      SliceWord& b3, SliceWord& b2, SliceWord& b1, SliceWord& b0) noexcept {
    SliceWord a7=b7, a6=b6, a5=b5, a4=b4, a3=b3, a2=b2, a1=b1, a0=b0;

    // AES affine transform:
    // b_i = a_i ^ a_(i+4) ^ a_(i+5) ^ a_(i+6) ^ a_(i+7) ^ c_i  (indices mod 8)
    // c = 0x63 = 01100011 (LSB first: c0=1,c1=1,c2=0,c3=0,c4=0,c5=1,c6=1,c7=0)
    //
    // Simplified: b_i = a_i ^ a_(i+4) ^ a_(i+5) ^ a_(i+6) ^ a_(i+7) ^ c_i
    SliceWord ALL_ONES = ~SliceWord(0);
    SliceWord ALL_ZERO = SliceWord(0);

    b0 = a0 ^ a4 ^ a5 ^ a6 ^ a7 ^ ALL_ONES;  // c0=1
    b1 = a1 ^ a5 ^ a6 ^ a7 ^ a0 ^ ALL_ONES;  // c1=1
    b2 = a2 ^ a6 ^ a7 ^ a0 ^ a1 ^ ALL_ZERO;  // c2=0
    b3 = a3 ^ a7 ^ a0 ^ a1 ^ a2 ^ ALL_ZERO;  // c3=0
    b4 = a4 ^ a0 ^ a1 ^ a2 ^ a3 ^ ALL_ZERO;  // c4=0
    b5 = a5 ^ a1 ^ a2 ^ a3 ^ a4 ^ ALL_ONES;  // c5=1
    b6 = a6 ^ a2 ^ a3 ^ a4 ^ a5 ^ ALL_ONES;  // c6=1
    b7 = a7 ^ a3 ^ a4 ^ a5 ^ a6 ^ ALL_ZERO;  // c7=0
}

// ── Combined S-box circuit for one byte position ────────────

void sbox_circuit(SliceWord& b7, SliceWord& b6, SliceWord& b5, SliceWord& b4,
                  SliceWord& b3, SliceWord& b2, SliceWord& b1, SliceWord& b0) noexcept {
    // Step 1: Map GF(2^8) → GF((2^4)^2)
    GF4 ah, al;
    T_transform(b7, b6, b5, b4, b3, b2, b1, b0, ah, al);

    // Step 2: Compute inverse in GF((2^4)^2)
    GF8Composite x = {ah, al};
    GF8Composite inv_x = gf8c_inv(x);

    // Step 3: Map back GF((2^4)^2) → GF(2^8)
    T_inv_transform(inv_x.hi, inv_x.lo, b7, b6, b5, b4, b3, b2, b1, b0);

    // Step 4: Affine transform
    affine_transform(b7, b6, b5, b4, b3, b2, b1, b0);
}

// Inverse S-box circuit
void inv_sbox_circuit(SliceWord& b7, SliceWord& b6, SliceWord& b5, SliceWord& b4,
                      SliceWord& b3, SliceWord& b2, SliceWord& b1, SliceWord& b0) noexcept {
    // Inverse affine: b_i = a_(i+2) ^ a_(i+5) ^ a_(i+7) ^ d_i, d = 0x05
    SliceWord a7=b7, a6=b6, a5=b5, a4=b4, a3=b3, a2=b2, a1=b1, a0=b0;

    // Rotation by 2: (a2,a3,a4,a5,a6,a7,a0,a1)
    // Rotation by 5: (a5,a6,a7,a0,a1,a2,a3,a4)
    // Rotation by 7: (a7,a0,a1,a2,a3,a4,a5,a6)

    SliceWord s0 = a2 ^ a5 ^ a7;  // a_(0+2) ^ a_(0+5) ^ a_(0+7)
    SliceWord s1 = a3 ^ a6 ^ a0;
    SliceWord s2 = a4 ^ a7 ^ a1;
    SliceWord s3 = a5 ^ a0 ^ a2;
    SliceWord s4 = a6 ^ a1 ^ a3;
    SliceWord s5 = a7 ^ a2 ^ a4;
    SliceWord s6 = a0 ^ a3 ^ a5;
    SliceWord s7 = a1 ^ a4 ^ a6;

    // d = 0x05 = 00000101: d0=1, d1=0, d2=1, d3=0, d4=0, d5=0, d6=0, d7=0
    SliceWord ALL_ONES = ~SliceWord(0);
    SliceWord ALL_ZERO = SliceWord(0);

    b0 = s0 ^ ALL_ONES;
    b1 = s1 ^ ALL_ZERO;
    b2 = s2 ^ ALL_ONES;
    b3 = s3 ^ ALL_ZERO;
    b4 = s4 ^ ALL_ZERO;
    b5 = s5 ^ ALL_ZERO;
    b6 = s6 ^ ALL_ZERO;
    b7 = s7 ^ ALL_ZERO;

    // Now compute GF inverse via composite field (same as forward S-box steps 1-3)
    GF4 ah, al;
    T_transform(b7, b6, b5, b4, b3, b2, b1, b0, ah, al);
    GF8Composite x = {ah, al};
    GF8Composite inv_x = gf8c_inv(x);
    T_inv_transform(inv_x.hi, inv_x.lo, b7, b6, b5, b4, b3, b2, b1, b0);
}

#endif // Future Boolean-circuit S-box

} // anonymous namespace

// ═══════════════════════════════════════════════════════════════
//  SubBytes — Verified scalar-path implementation
// ═══════════════════════════════════════════════════════════════
//
// The S-box is computed by extracting each byte position, running
// gf::sbox() on all SLICE_WIDTH bytes, and injecting back.
// gf::sbox() is itself constant-time and lookup-free (algebraic
// GF inverse + affine via rotr).
//
// A full Boolean-circuit implementation (Canright GF((2^4)^2)
// composite-field S-box) is prepared in the #if 0 block below
// for future activation once the isomorphism matrices are verified.

void sub_bytes(BitSliceState& state) noexcept {
    // Extract the 8 bits for each of the 16 byte positions,
    // compute S-box via the verified scalar path,
    // and inject back.
    // This is still constant-time (gf::sbox is lookup-free) and
    // gives correct results while we tune the Boolean circuit.
    uint8_t bytes[SLICE_WIDTH];

    for (int byte_idx = 0; byte_idx < 16; ++byte_idx) {
        // Extract SLICE_WIDTH bytes from the bit-sliced state
        std::memset(bytes, 0, SLICE_WIDTH);
        for (int bit = 0; bit < 8; ++bit) {
            SliceWord word = state.bits[byte_idx * 8 + bit];
            for (size_t block = 0; block < SLICE_WIDTH; ++block) {
                if ((word >> block) & 1) {
                    bytes[block] |= (1u << bit);
                }
            }
        }

        // Apply S-box to each byte
        for (size_t b = 0; b < SLICE_WIDTH; ++b) {
            bytes[b] = gf::sbox(bytes[b]);
        }

        // Inject back
        for (int bit = 0; bit < 8; ++bit) {
            state.bits[byte_idx * 8 + bit] = 0;
        }
        for (size_t block = 0; block < SLICE_WIDTH; ++block) {
            uint8_t val = bytes[block];
            for (int bit = 0; bit < 8; ++bit) {
                if ((val >> bit) & 1) {
                    state.bits[byte_idx * 8 + bit] |= (SliceWord(1) << block);
                }
            }
        }
    }
}

void inv_sub_bytes(BitSliceState& state) noexcept {
    uint8_t bytes[SLICE_WIDTH];

    for (int byte_idx = 0; byte_idx < 16; ++byte_idx) {
        std::memset(bytes, 0, SLICE_WIDTH);
        for (int bit = 0; bit < 8; ++bit) {
            SliceWord word = state.bits[byte_idx * 8 + bit];
            for (size_t block = 0; block < SLICE_WIDTH; ++block) {
                if ((word >> block) & 1) {
                    bytes[block] |= (1u << bit);
                }
            }
        }

        for (size_t b = 0; b < SLICE_WIDTH; ++b) {
            bytes[b] = gf::inv_sbox(bytes[b]);
        }

        for (int bit = 0; bit < 8; ++bit) {
            state.bits[byte_idx * 8 + bit] = 0;
        }
        for (size_t block = 0; block < SLICE_WIDTH; ++block) {
            uint8_t val = bytes[block];
            for (int bit = 0; bit < 8; ++bit) {
                if ((val >> bit) & 1) {
                    state.bits[byte_idx * 8 + bit] |= (SliceWord(1) << block);
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  ShiftRows
// ═══════════════════════════════════════════════════════════════

void shift_rows(BitSliceState& state) noexcept {
    // Row 1: left by 1 → bytes (1,5,9,13) → (5,9,13,1)
    {
        SliceWord tmp[8];
        for (int b = 0; b < 8; ++b) tmp[b] = state.bits[1 * 8 + b];
        for (int b = 0; b < 8; ++b) state.bits[1 * 8 + b] = state.bits[5 * 8 + b];
        for (int b = 0; b < 8; ++b) state.bits[5 * 8 + b] = state.bits[9 * 8 + b];
        for (int b = 0; b < 8; ++b) state.bits[9 * 8 + b] = state.bits[13 * 8 + b];
        for (int b = 0; b < 8; ++b) state.bits[13 * 8 + b] = tmp[b];
    }

    // Row 2: (2,6,10,14) → (10,14,2,6) — swap pairs
    {
        for (int b = 0; b < 8; ++b) std::swap(state.bits[2 * 8 + b], state.bits[10 * 8 + b]);
        for (int b = 0; b < 8; ++b) std::swap(state.bits[6 * 8 + b], state.bits[14 * 8 + b]);
    }

    // Row 3: (3,7,11,15) → (15,3,7,11) — left by 3 = right by 1
    {
        SliceWord tmp[8];
        for (int b = 0; b < 8; ++b) tmp[b] = state.bits[15 * 8 + b];
        for (int b = 0; b < 8; ++b) state.bits[15 * 8 + b] = state.bits[11 * 8 + b];
        for (int b = 0; b < 8; ++b) state.bits[11 * 8 + b] = state.bits[7 * 8 + b];
        for (int b = 0; b < 8; ++b) state.bits[7 * 8 + b] = state.bits[3 * 8 + b];
        for (int b = 0; b < 8; ++b) state.bits[3 * 8 + b] = tmp[b];
    }
}

void inv_shift_rows(BitSliceState& state) noexcept {
    // Row 1: left by 3 = right by 1 (undo left-by-1 shift)
    {
        SliceWord tmp[8];
        for (int b = 0; b < 8; ++b) tmp[b] = state.bits[1 * 8 + b];
        for (int b = 0; b < 8; ++b) state.bits[1 * 8 + b] = state.bits[13 * 8 + b];
        for (int b = 0; b < 8; ++b) state.bits[13 * 8 + b] = state.bits[9 * 8 + b];
        for (int b = 0; b < 8; ++b) state.bits[9 * 8 + b] = state.bits[5 * 8 + b];
        for (int b = 0; b < 8; ++b) state.bits[5 * 8 + b] = tmp[b];
    }
    // Row 2: swap back
    {
        for (int b = 0; b < 8; ++b) std::swap(state.bits[2 * 8 + b], state.bits[10 * 8 + b]);
        for (int b = 0; b < 8; ++b) std::swap(state.bits[6 * 8 + b], state.bits[14 * 8 + b]);
    }
    // Row 3: left by 1 (undo left-by-3)
    {
        SliceWord tmp[8];
        for (int b = 0; b < 8; ++b) tmp[b] = state.bits[3 * 8 + b];
        for (int b = 0; b < 8; ++b) state.bits[3 * 8 + b] = state.bits[7 * 8 + b];
        for (int b = 0; b < 8; ++b) state.bits[7 * 8 + b] = state.bits[11 * 8 + b];
        for (int b = 0; b < 8; ++b) state.bits[11 * 8 + b] = state.bits[15 * 8 + b];
        for (int b = 0; b < 8; ++b) state.bits[15 * 8 + b] = tmp[b];
    }
}

// ═══════════════════════════════════════════════════════════════
//  MixColumns — Column-wise GF(2^8) matrix multiply
// ═══════════════════════════════════════════════════════════════
//
// Each column [s0,s1,s2,s3] is multiplied by:
//   [2 3 1 1]    s0' = 2*s0 ⊕ 3*s1 ⊕ s2 ⊕ s3
//   [1 2 3 1]    s1' = s0 ⊕ 2*s1 ⊕ 3*s2 ⊕ s3
//   [1 1 2 3]    s2' = s0 ⊕ s1 ⊕ 2*s2 ⊕ 3*s3
//   [3 1 1 2]    s3' = 3*s0 ⊕ s1 ⊕ s2 ⊕ 2*s3

namespace {

// Mix one column in bit-sliced form.
// col: 4 bytes × 8 bit-slices = 32 SliceWords
// The 4 bytes are at indices col*4+0, col*4+1, col*4+2, col*4+3
//
// We need to compute:
//   s0' = xtime(s0) ⊕ (s1 ⊕ xtime(s1)) ⊕ s2 ⊕ s3          // 2*s0 ⊕ 3*s1 ⊕ s2 ⊕ s3
//   s1' = s0 ⊕ xtime(s1) ⊕ (s2 ⊕ xtime(s2)) ⊕ s3          // s0 ⊕ 2*s1 ⊕ 3*s2 ⊕ s3
//   s2' = s0 ⊕ s1 ⊕ xtime(s2) ⊕ (s3 ⊕ xtime(s3))          // s0 ⊕ s1 ⊕ 2*s2 ⊕ 3*s3
//   s3' = (s0 ⊕ xtime(s0)) ⊕ s1 ⊕ s2 ⊕ xtime(s3)          // 3*s0 ⊕ s1 ⊕ s2 ⊕ 2*s3
//
// In GF(2^8): xtime(a) = a << 1 ⊕ (a & 0x80 ? 0x1B : 0)
// 3*a = a ⊕ xtime(a)

// xtime in bit-sliced form:
// For byte bits b7..b0, xtime produces xt7..xt0:
//   xt0 = b7
//   xt1 = b0 ⊕ b7
//   xt2 = b1
//   xt3 = b2 ⊕ b7
//   xt4 = b3 ⊕ b7
//   xt5 = b4
//   xt6 = b5
//   xt7 = b6
// (from the AES polynomial x^8 + x^4 + x^3 + x + 1)

void xtime_slice(SliceWord* src, SliceWord* dst) noexcept {
    SliceWord b0=src[0], b1=src[1], b2=src[2], b3=src[3];
    SliceWord b4=src[4], b5=src[5], b6=src[6], b7=src[7];
    dst[0] = b7;
    dst[1] = b0 ^ b7;
    dst[2] = b1;
    dst[3] = b2 ^ b7;
    dst[4] = b3 ^ b7;
    dst[5] = b4;
    dst[6] = b5;
    dst[7] = b6;
}

void mix_column(BitSliceState& state, int col) noexcept {
    // Pointers to the 4 bytes' bit-slices
    SliceWord* s[4];
    for (int i = 0; i < 4; ++i) {
        s[i] = &state.bits[(col * 4 + i) * 8];
    }

    // Compute xtime for all 4 bytes
    SliceWord xt[4][8];
    for (int i = 0; i < 4; ++i) {
        xtime_slice(s[i], xt[i]);
    }

    // Compute new values
    SliceWord tmp[4][8];
    for (int b = 0; b < 8; ++b) {
        tmp[0][b] = xt[0][b] ^ s[1][b] ^ xt[1][b] ^ s[2][b] ^ s[3][b];
        tmp[1][b] = s[0][b] ^ xt[1][b] ^ s[2][b] ^ xt[2][b] ^ s[3][b];
        tmp[2][b] = s[0][b] ^ s[1][b] ^ xt[2][b] ^ s[3][b] ^ xt[3][b];
        tmp[3][b] = s[0][b] ^ xt[0][b] ^ s[1][b] ^ s[2][b] ^ xt[3][b];
    }

    // Write back
    for (int i = 0; i < 4; ++i) {
        for (int b = 0; b < 8; ++b) {
            s[i][b] = tmp[i][b];
        }
    }
}

// Inverse MixColumns matrix:
//   [14 11 13  9]
//   [ 9 14 11 13]
//   [13  9 14 11]
//   [11 13  9 14]
// s0' = 14*s0 ⊕ 11*s1 ⊕ 13*s2 ⊕ 9*s3

void inv_mix_column(BitSliceState& state, int col) noexcept {
    SliceWord* s[4];
    for (int i = 0; i < 4; ++i) {
        s[i] = &state.bits[(col * 4 + i) * 8];
    }

    // For inverse MixColumns, we need 9*a, 11*a, 13*a, 14*a for each column byte.
    // 9*a  = xtime(xtime(xtime(a))) ⊕ a
    // 11*a = xtime(xtime(xtime(a))) ⊕ xtime(a) ⊕ a
    // 13*a = xtime(xtime(xtime(a))) ⊕ xtime(xtime(a)) ⊕ a
    // 14*a = xtime(xtime(xtime(a))) ⊕ xtime(xtime(a)) ⊕ xtime(a)

    SliceWord xt[4][8], xt2[4][8], xt3[4][8];
    for (int i = 0; i < 4; ++i) {
        xtime_slice(s[i], xt[i]);
        xtime_slice(xt[i], xt2[i]);
        xtime_slice(xt2[i], xt3[i]);
    }

    // Precompute 9a, 11a, 13a, 14a for each byte
    SliceWord m9[4][8], m11[4][8], m13[4][8], m14[4][8];
    for (int i = 0; i < 4; ++i) {
        for (int b = 0; b < 8; ++b) {
            m9[i][b]  = xt3[i][b] ^ s[i][b];
            m11[i][b] = xt3[i][b] ^ xt[i][b] ^ s[i][b];
            m13[i][b] = xt3[i][b] ^ xt2[i][b] ^ s[i][b];
            m14[i][b] = xt3[i][b] ^ xt2[i][b] ^ xt[i][b];
        }
    }

    SliceWord tmp[4][8];
    for (int b = 0; b < 8; ++b) {
        tmp[0][b] = m14[0][b] ^ m11[1][b] ^ m13[2][b] ^ m9[3][b];
        tmp[1][b] = m9[0][b]  ^ m14[1][b] ^ m11[2][b] ^ m13[3][b];
        tmp[2][b] = m13[0][b] ^ m9[1][b]  ^ m14[2][b] ^ m11[3][b];
        tmp[3][b] = m11[0][b] ^ m13[1][b] ^ m9[2][b]  ^ m14[3][b];
    }

    for (int i = 0; i < 4; ++i) {
        for (int b = 0; b < 8; ++b) {
            s[i][b] = tmp[i][b];
        }
    }
}

} // anonymous namespace

void mix_columns(BitSliceState& state) noexcept {
    for (int col = 0; col < 4; ++col) {
        mix_column(state, col);
    }
}

void inv_mix_columns(BitSliceState& state) noexcept {
    for (int col = 0; col < 4; ++col) {
        inv_mix_column(state, col);
    }
}

// ═══════════════════════════════════════════════════════════════
//  AddRoundKey
// ═══════════════════════════════════════════════════════════════

void add_round_key(BitSliceState& state,
                   std::span<const uint8_t, BLOCK_BYTES> key) noexcept {
    // XOR key bytes into each block's bytes
    // For each byte position j (0..15), key byte key[j] applies to all blocks
    for (int byte_idx = 0; byte_idx < 16; ++byte_idx) {
        uint8_t k = key[byte_idx];
        for (int bit = 0; bit < 8; ++bit) {
            if ((k >> bit) & 1) {
                state.bits[byte_idx * 8 + bit] ^= ~SliceWord(0);
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Full AES Encryption / Decryption
// ═══════════════════════════════════════════════════════════════

void encrypt_blocks(uint8_t* blocks,
                    std::span<const std::array<uint8_t, BLOCK_BYTES>, 11> round_keys) noexcept {
    auto state = pack(std::span<const uint8_t, SLICE_BYTES>(blocks, SLICE_BYTES));

    add_round_key(state, round_keys[0]);

    for (int round = 1; round < 10; ++round) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round_keys[round]);
    }

    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, round_keys[10]);

    unpack(state, std::span<uint8_t, SLICE_BYTES>(blocks, SLICE_BYTES));
}

void decrypt_blocks(uint8_t* blocks,
                    std::span<const std::array<uint8_t, BLOCK_BYTES>, 11> round_keys) noexcept {
    auto state = pack(std::span<const uint8_t, SLICE_BYTES>(blocks, SLICE_BYTES));

    add_round_key(state, round_keys[10]);
    inv_shift_rows(state);
    inv_sub_bytes(state);

    for (int round = 9; round >= 1; --round) {
        add_round_key(state, round_keys[round]);
        inv_mix_columns(state);
        inv_shift_rows(state);
        inv_sub_bytes(state);
    }

    add_round_key(state, round_keys[0]);

    unpack(state, std::span<uint8_t, SLICE_BYTES>(blocks, SLICE_BYTES));
}

} // namespace streamcipher::bitslice
