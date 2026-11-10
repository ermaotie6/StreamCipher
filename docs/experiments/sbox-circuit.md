# 未验证的 S-box 电路实验归档

此代码从 `src/core/bitslice.cpp` 的禁用区移出，仅供研究；未通过正确性验证，不编译、不导出、不属于当前能力。当前 SubBytes 使用代数 S-box。启用任何替代实现前必须重新通过标准向量、逐值 S-box 对照和互操作验证。

```cpp
#if 0  // ---- 下面这套布尔电路矩阵没调通，先封印 ----

// GF(2^4) 的四则运算，每个元素用 4 个 SliceWord 表示 (w3,w2,w1,w0)

using GF4 = std::array<SliceWord, 4>;

// GF(2^4) 乘法，模 x^4+x+1
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
        t9 ^ tA ^ tB ^ (a0 ^ a3) & b3,
        t8 ^ (a0 ^ a3) & b1 ^ t5 ^ t6,
        t7 ^ t1  ^ tC ^ tD,
        t3 ^ t0  ^ t1 ^ t2
    };
}

// GF(2^4) 平方
[[nodiscard]] GF4 gf4_sq(const GF4& a) noexcept {
    return {a[3], a[1] ^ a[3], a[2], a[0] ^ a[2]};
}

// GF(2^4) 逆元，暴力真值表化简出来的
[[nodiscard]] GF4 gf4_inv(const GF4& a) noexcept {
    SliceWord a0=a[0], a1=a[1], a2=a[2], a3=a[3];

    SliceWord t0 = a1 ^ a2 ^ a3 ^ (a0 & a1 & a2) ^ (a0 & a1 & a3) ^ (a0 & a2 & a3);
    SliceWord t1 = a0 ^ a1 ^ a0 & a2 ^ a1 & a2 ^ a0 & a1 & a3 ^ a0 & a2 & a3;
    SliceWord t2 = a0 ^ a1 ^ a2 ^ a0 & a3 ^ a1 & a3 ^ a0 & a1 & a2 ^ a0 & a2 & a3;
    SliceWord t3 = a1 ^ a2 ^ a3 ^ a0 & a1 ^ a0 & a2 ^ a1 & a2 ^ a0 & a1 & a3;

    return {t3, t2, t1, t0};
}

// 乘常数 λ=0x6（GF(2^4) 里面 ω^2+ω 的结果）
[[nodiscard]] GF4 gf4_mul_lambda(const GF4& a) noexcept {
    SliceWord a0=a[0], a1=a[1], a2=a[2], a3=a[3];
    return {a2 ^ a0, a1 ^ a3, a0 ^ a3, a3};
}

// GF((2^4)^2) 的元素：高4位 + 低4位
struct GF8Composite { GF4 hi, lo; };

// GF((2^4)^2) 的逆元： (a_h*y + a_l)^(-1) = a_h*d*y + (a_h+a_l)*d
// 其中 d = (a_h^2*λ + a_h*a_l + a_l^2)^(-1)
[[nodiscard]] GF8Composite gf8c_inv(const GF8Composite& x) noexcept {
    GF4 ah2   = gf4_sq(x.hi);
    GF4 al2   = gf4_sq(x.lo);
    GF4 ahal  = gf4_mul(x.hi, x.lo);
    GF4 tmp   = gf4_mul_lambda(ah2);
    GF4 sum   = { tmp[3]^ahal[3]^al2[3], tmp[2]^ahal[2]^al2[2],
                  tmp[1]^ahal[1]^al2[1], tmp[0]^ahal[0]^al2[0] };
    GF4 d     = gf4_inv(sum);
    GF4 r_hi  = gf4_mul(x.hi, d);
    GF4 ah_al = { x.hi[3]^x.lo[3], x.hi[2]^x.lo[2],
                  x.hi[1]^x.lo[1], x.hi[0]^x.lo[0] };
    GF4 r_lo  = gf4_mul(ah_al, d);
    return {r_hi, r_lo};
}

// 同构映射 T: GF(2^8) → GF((2^4)^2)
// 这里的两套 4×8 矩阵是 Canright 论文里给的标准形式
// 但我算了几遍跟 NIST 向量对不上，怀疑是 λ 的取值或者基的选择有问题
// TODO: 对着论文重新推一遍矩阵系数

void T_transform(SliceWord b7, SliceWord b6, SliceWord b5, SliceWord b4,
                 SliceWord b3, SliceWord b2, SliceWord b1, SliceWord b0,
                 GF4& ah, GF4& al) noexcept {
    ah[3] = b7 ^ b5;
    ah[2] = b7 ^ b6 ^ b4 ^ b3 ^ b2 ^ b1;
    ah[1] = b7 ^ b5 ^ b3 ^ b2;
    ah[0] = b7 ^ b6 ^ b3 ^ b2 ^ b1 ^ b0;
    al[3] = b7 ^ b6 ^ b5 ^ b3;
    al[2] = b6 ^ b4;
    al[1] = b7 ^ b6 ^ b5 ^ b4 ^ b3;
    al[0] = b6 ^ b5 ^ b4 ^ b2 ^ b1 ^ b0;
}

void T_inv_transform(const GF4& ah, const GF4& al,
                     SliceWord& b7, SliceWord& b6, SliceWord& b5, SliceWord& b4,
                     SliceWord& b3, SliceWord& b2, SliceWord& b1, SliceWord& b0) noexcept {
    b7 = ah[3] ^ ah[2] ^ ah[1] ^ al[3] ^ al[0];
    b6 = ah[2] ^ ah[0] ^ al[3] ^ al[1];
    b5 = ah[0] ^ al[2] ^ al[0];
    b4 = ah[3] ^ ah[2] ^ ah[0] ^ al[2] ^ al[1];
    b3 = ah[3] ^ ah[1] ^ ah[0] ^ al[2] ^ al[1] ^ al[0];
    b2 = ah[3] ^ ah[2] ^ al[3];
    b1 = ah[3] ^ ah[2] ^ ah[0] ^ al[3] ^ al[0];
    b0 = ah[3] ^ ah[2] ^ ah[1] ^ ah[0] ^ al[3] ^ al[2] ^ al[1];
}

// 正向仿射，c=0x63
void affine_transform(SliceWord& b7, SliceWord& b6, SliceWord& b5, SliceWord& b4,
                      SliceWord& b3, SliceWord& b2, SliceWord& b1, SliceWord& b0) noexcept {
    SliceWord a7=b7, a6=b6, a5=b5, a4=b4, a3=b3, a2=b2, a1=b1, a0=b0;
    SliceWord ONES = ~SliceWord(0), ZERO = SliceWord(0);
    b0 = a0 ^ a4 ^ a5 ^ a6 ^ a7 ^ ONES;
    b1 = a1 ^ a5 ^ a6 ^ a7 ^ a0 ^ ONES;
    b2 = a2 ^ a6 ^ a7 ^ a0 ^ a1 ^ ZERO;
    b3 = a3 ^ a7 ^ a0 ^ a1 ^ a2 ^ ZERO;
    b4 = a4 ^ a0 ^ a1 ^ a2 ^ a3 ^ ZERO;
    b5 = a5 ^ a1 ^ a2 ^ a3 ^ a4 ^ ONES;
    b6 = a6 ^ a2 ^ a3 ^ a4 ^ a5 ^ ONES;
    b7 = a7 ^ a3 ^ a4 ^ a5 ^ a6 ^ ZERO;
}

void sbox_circuit(SliceWord& b7, SliceWord& b6, SliceWord& b5, SliceWord& b4,
                  SliceWord& b3, SliceWord& b2, SliceWord& b1, SliceWord& b0) noexcept {
    GF4 ah, al;
    T_transform(b7, b6, b5, b4, b3, b2, b1, b0, ah, al);
    GF8Composite x = {ah, al};
    GF8Composite inv_x = gf8c_inv(x);
    T_inv_transform(inv_x.hi, inv_x.lo, b7, b6, b5, b4, b3, b2, b1, b0);
    affine_transform(b7, b6, b5, b4, b3, b2, b1, b0);
}

// 逆S-box：先逆仿射（d=0x05），再走同样的 GF((2^4)^2) 逆元
void inv_sbox_circuit(SliceWord& b7, SliceWord& b6, SliceWord& b5, SliceWord& b4,
                      SliceWord& b3, SliceWord& b2, SliceWord& b1, SliceWord& b0) noexcept {
    SliceWord a7=b7, a6=b6, a5=b5, a4=b4, a3=b3, a2=b2, a1=b1, a0=b0;
    SliceWord ONES = ~SliceWord(0), ZERO = SliceWord(0);
    SliceWord s0 = a2 ^ a5 ^ a7,  s1 = a3 ^ a6 ^ a0;
    SliceWord s2 = a4 ^ a7 ^ a1,  s3 = a5 ^ a0 ^ a2;
    SliceWord s4 = a6 ^ a1 ^ a3,  s5 = a7 ^ a2 ^ a4;
    SliceWord s6 = a0 ^ a3 ^ a5,  s7 = a1 ^ a4 ^ a6;
    b0 = s0 ^ ONES;  b1 = s1 ^ ZERO;  b2 = s2 ^ ONES;  b3 = s3 ^ ZERO;
    b4 = s4 ^ ZERO;  b5 = s5 ^ ZERO;  b6 = s6 ^ ZERO;  b7 = s7 ^ ZERO;

    GF4 ah, al;
    T_transform(b7, b6, b5, b4, b3, b2, b1, b0, ah, al);
    GF8Composite x = {ah, al};
    GF8Composite inv_x = gf8c_inv(x);
    T_inv_transform(inv_x.hi, inv_x.lo, b7, b6, b5, b4, b3, b2, b1, b0);
}

#endif // 布尔电路 S-box (矩阵没调通)
```
