# StreamCipher 详细实现文档

## 目录

1. [项目背景与设计目标](#1-项目背景与设计目标)
2. [总体架构](#2-总体架构)
3. [数学基础：有限域 GF(2⁸)](#3-数学基础有限域-gf2⁸)
4. [Bit-slicing 位切片层](#4-bit-slicing-位切片层)
5. [AES-128 密码核心](#5-aes-128-密码核心)
6. [密码工作模式：CTR 与 GCM](#6-密码工作模式ctr-与-gcm)
7. [流式处理框架](#7-流式处理框架)
8. [SIMD 硬件加速层](#8-simd-硬件加速层)
9. [内存管理子系统](#9-内存管理子系统)
10. [关键实现决策与调试记录](#10-关键实现决策与调试记录)
11. [测试策略与覆盖度](#11-测试策略与覆盖度)
12. [性能分析框架](#12-性能分析框架)

---

## 1. 项目背景与设计目标

### 1.1 问题陈述

现代云计算与物联网（IoT）场景对海量数据实时传输提出了极高的安全需求。然而，传统通用密码库（如 OpenSSL）存在以下瓶颈：

- **体积庞大**：OpenSSL 包含数百种算法和协议，动态库大小超过 3 MB；
- **内存开销大**：内部频繁使用动态内存分配与数据拷贝；
- **缓存命中率低**：S-box 查表操作导致缓存侧信道攻击面，且在流式处理中缓存局部性差；
- **轻量设备不友好**：IoT 设备内存和计算资源有限，传统库的运行时代价过高。

### 1.2 设计目标

StreamCipher 从底层重构对称加密引擎，针对性解决上述问题：

| 目标 | 实现策略 |
|------|----------|
| **代数化 S-box** | 用纯位运算实现 GF(2⁸) 乘法与逆元，消除 256 字节 S-box 查表 |
| **零拷贝流式框架** | C++20 `std::span` 全程零拷贝传递缓冲区，内存开销恒定 O(1) |
| **Bit-slicing 并行** | 一次处理 8 个 AES 块，每个 bit 位置组成一个机器字进行布尔电路运算 |
| **SIMD 硬件加速** | x86_64 下集成 AES-NI 与 AVX2 指令集，理论吞吐提升 4-8× |
| **缓存友好** | 自定义 SlabPool 内存池 + 64 字节对齐的 bit-slice 数据结构 |

### 1.3 技术路线

```
代数理论推导 → 基础 C++ 逻辑实现 → 内存池与零拷贝架构重构 → SIMD 指令集加速 → Linux 应用封装
```

---

## 2. 总体架构

### 2.1 分层架构图

```
┌──────────────────────────────────────────────┐
│  apps/          scipher CLI (encrypt/decrypt/benchmark)  │  ← 用户层
├──────────────────────────────────────────────┤
│  examples/      encrypt_file / decrypt_file              │  ← 示例
├──────────────────────────────────────────────┤
│  stream/        StreamProcessor (CTR/GCM)                │  ← 模式层
│                 FilePipeline   (文件 I/O 编排)           │
├──────────────────────────────────────────────┤
│  core/aes.cpp   AES-128 (scalar / bit-sliced / AES-NI)   │  ← 密码核心
│  core/bitslice   Bit-sliced SubBytes/Shift/Mix/AddRK     │
│  core/gf         GF(2⁸) 纯位运算 mul/inv/xtime          │
│  core/cipher     密码模式 CTR / GCM (含 GHASH)          │
├──────────────────────────────────────────────┤
│  simd/           Vec128/Vec256 向量 + AES-NI 内联        │  ← 硬件加速
├──────────────────────────────────────────────┤
│  memory/         SlabPool 内存池 + span_utils            │  ← 内存管理
└──────────────────────────────────────────────┘
```

### 2.2 文件树

```
streamcipher/
├── CMakeLists.txt                    # 顶层 CMake，C++20，x86_64 检测
├── README.md                         # 项目总览
├── LICENSE                           # MIT
├── cmake/
│   └── DetectArch.cmake              # 架构检测 (x86_64 / aarch64 / generic)
├── include/streamcipher/
│   ├── streamcipher.hpp              # 伞形头文件
│   ├── core/
│   │   ├── gf.hpp                    # GF(2⁸) 类型与运算声明
│   │   ├── bitslice.hpp              # Bit-slice 数据结构与操作声明
│   │   ├── aes.hpp                   # AES-128 API 声明
│   │   └── cipher.hpp                # 密码模式抽象接口
│   ├── stream/
│   │   ├── stream.hpp                # StreamProcessor 接口
│   │   └── pipeline.hpp              # FilePipeline 接口
│   ├── simd/
│   │   ├── simd.hpp                  # SIMD 向量类型与操作
│   │   └── aesni.hpp                 # AES-NI 指令封装
│   └── memory/
│       ├── pool.hpp                  # SlabPool 模板 (header-only)
│       └── span_utils.hpp            # std::span 工具函数
├── src/                              # 实现文件 (镜像 include 结构)
│   ├── core/
│   │   ├── gf.cpp
│   │   ├── bitslice.cpp
│   │   ├── aes.cpp
│   │   └── cipher.cpp
│   ├── stream/
│   │   ├── stream.cpp
│   │   └── pipeline.cpp
│   ├── simd/
│   │   ├── simd.cpp
│   │   └── aesni.cpp
│   └── memory/
│       ├── pool.cpp
│       └── span_utils.cpp
├── tests/                            # Catch2 单元测试
│   ├── test_gf.cpp                   # GF 运算 12 用例 67581 断言
│   ├── test_aes.cpp                  # AES NIST 向量 + bit-sliced 往返
│   ├── test_stream.cpp               # CTR/GCM 流式 + 分块
│   └── test_simd.cpp                 # SIMD 操作 + 特性检测
├── benchmarks/                       # Google Benchmark
│   ├── bench_gf.cpp
│   ├── bench_aes.cpp
│   └── bench_stream.cpp
├── examples/
│   ├── encrypt_file.cpp
│   └── decrypt_file.cpp
├── apps/
│   └── main.cpp                      # scipher CLI 工具
├── docs/
│   ├── architecture.md
│   ├── api.md
│   └── implementation.md             # 本文档
└── scripts/
    ├── build.sh
    └── benchmark.sh
```

---

## 3. 数学基础：有限域 GF(2⁸)

### 3.1 域的定义

GF(2⁸) 是包含 256 个元素的有限域，其元素可表示为 8 位二进制多项式。AES 标准使用的不可约多项式为：

```
m(x) = x⁸ + x⁴ + x³ + x + 1
```

对应的十六进制表示为 `0x11B`，去掉 x⁸ 项后得到 `0x1B`，即代码中的 `IRREDUCIBLE_POLY`。

### 3.2 乘法实现 (`gf::mul`)

**算法**：标准移位加法（shift-and-add），固定 8 次迭代保证常数时间。

```
result = 0
for i = 0 to 7:
    if b₀ == 1:
        result = result XOR a                           // (1)
    carry = a₇                                          // (2)
    a = (a << 1) XOR (carry ? 0x1B : 0)                // (3)
    b = b >> 1                                          // (4)
return result
```

**步骤详解**：
1. **(1) 条件累加**：使用 `a & -(b & 1)` 实现无分支的条件 XOR —— `-(b&1)` 在 b 的 LSB 为 1 时产生全 1 掩码 (0xFF)，为 0 时产生全 0。这是常数时间的关键。
2. **(2) 进位检测**：检查 a 的最高位是否溢出。
3. **(3) 模约简**：左移 a，若溢出则异或不可约多项式进行模运算。
4. **(4) 移位**：b 右移一位，处理下一个 bit。

**常数时间保证**：无论 b 的值如何，循环始终执行 8 次，无提前退出。条件操作通过位掩码而非分支实现。

### 3.3 逆元计算 (`gf::inv`)

利用费马小定理：在 GF(2⁸) 中，对任意非零元素 a，有 a^(2⁸-2) = a^254 = a⁻¹。

**算法**：二进制快速幂（exponentiation by squaring）。

```
result = 1
for i = 7 downto 0:           // 254 = 0b11111110
    result = result * result  // 平方
    if bit_i(254) == 1:
        result = result * a   // 乘以基数
return result
```

**性能特征**：每个逆元计算需要 7 次平方 + 7 次乘法 = 14 次 GF(2⁸) 乘法。

### 3.4 xtime 操作

`xtime(a) = a × x` 是乘以多项式 x（即 0x02）的特化快速路径：

```
if a₇ == 1:
    return (a << 1) XOR 0x1B
else:
    return (a << 1)
```

在 MixColumns 中被大量使用，单独实现以避免通用乘法的开销。

### 3.5 S-box 代数实现

传统 AES S-box 是一个 256 字节的预计算查表。StreamCipher 通过代数推导，完全消除了这张表：

```
S(x) = Affine(GF_inv(x))
```

其中 `Affine` 是仿射变换：

```
bᵢ = aᵢ ⊕ a₍ᵢ₊₄₎ ⊕ a₍ᵢ₊₅₎ ⊕ a₍ᵢ₊₆₎ ⊕ a₍ᵢ₊₇₎ ⊕ cᵢ    (索引 mod 8)
c  = 0x63
```

**C++ 实现**（`gf::sbox`）：
```cpp
GF8 inv_a = inv(a);                    // GF 逆元
GF8 result = inv_a;
result ^= std::rotr(inv_a, 4);        // a₍ᵢ₊₄₎
result ^= std::rotr(inv_a, 5);        // a₍ᵢ₊₅₎
result ^= std::rotr(inv_a, 6);        // a₍ᵢ₊₆₎
result ^= std::rotr(inv_a, 7);        // a₍ᵢ₊₇₎
result ^= 0x63;                       // 常数项
```

**逆 S-box**（`gf::inv_sbox`）：
```
inv_S(x) = GF_inv(InvAffine(x))
```
逆仿射变换不含 aᵢ 项（与正向仿射的关键区别）：
```
bᵢ' = a₍ᵢ₊₂₎ ⊕ a₍ᵢ₊₅₎ ⊕ a₍ᵢ₊₇₎ ⊕ dᵢ
d   = 0x05
```

### 3.6 验证

NIST 标准测试向量验证：`sbox(0x00) = 0x63`, `sbox(0x53) = 0xED`, `sbox(0xAB) = 0x62`。全表往返验证：`inv_sbox(sbox(x)) == x` 对所有 256 个输入成立。

---

## 4. Bit-slicing 位切片层

### 4.1 核心思想

Bit-slicing 是 Käsper & Schwabe (CHES 2009) 提出的一种 SIMD-within-a-register (SWAR) 技术。其核心思路是将 B 个 AES 块的数据重新排列：不是按字节存储，而是将每个 bit 位置上所有 B 个块的值打包成一个机器字。

**直观理解**：

```
传统布局：
Block 0:  [b₀₀ b₀₁ ... b₀₁₂₇]
Block 1:  [b₁₀ b₁₁ ... b₁₁₂₇]
...
Block 7:  [b₇₀ b₇₁ ... b₇₁₂₇]

Bit-sliced 布局：
Word 0:   [b₀₀ b₁₀ b₂₀ b₃₀ b₄₀ b₅₀ b₆₀ b₇₀]  ← 所有块的 bit 0
Word 1:   [b₀₁ b₁₁ b₂₁ b₃₁ b₄₁ b₅₁ b₆₁ b₇₁]  ← 所有块的 bit 1
...
Word 127: [b₀₁₂₇ b₁₁₂₇ ... b₇₁₂₇]             ← 所有块的 bit 127
```

### 4.2 数据结构

```cpp
constexpr size_t SLICE_WIDTH = 8;        // 一次处理 8 个块
using SliceWord = uint8_t;               // 每个字 8 位（每块 1 位）
struct alignas(64) BitSliceState {
    SliceWord bits[128];                 // 128 个 bit 位置 × 8 个块 = 1024 bits = 128 bytes
};
```

**对齐设计**：`alignas(64)` 确保整个状态驻留在单条缓存行内（实际只占用 128 字节，64 字节对齐保证不会跨两条缓存行）。

### 4.3 Pack / Unpack

**Pack**：将 8 个 16 字节块转换为 128 个 bit-slice word。

```cpp
for bit = 0..127:
    byte_idx = bit / 8       // 哪个字节 (0..15)
    bit_in_byte = bit % 8    // 字节内的哪个位 (0..7)
    word = 0
    for block = 0..7:
        if block[block][byte_idx] 的第 bit_in_byte 位为 1:
            word |= (1 << block)
    state.bits[bit] = word
```

**Unpack**：逆操作，将 bit-slice 状态恢复为 8 个字节块。

### 4.4 SubBytes 在 Bit-sliced 域中的实现

当前实现采用 "提取-变换-注入" 策略：

1. **提取**：对于 16 个字节位置中的每一个，从 8 个 bit-slice word 中提取出 8 个字节
2. **变换**：对每个字节调用标量 `gf::sbox()`（已保证常数时间，无查表）
3. **注入**：将变换后的字节重新写回 8 个 bit-slice word

注意：未来将替换为完全在 bit-sliced 域中操作的 Canright 组合域 S-box 电路（已在代码中准备了 `gf4_mul`、`gf4_sq`、`gf4_inv`、`T_transform` 等 GF((2⁴)²) 子运算），以获得更好的并行度。

### 4.5 ShiftRows 在 Bit-sliced 域中的实现

ShiftRows 操作于字节级别。在 bit-sliced 域中，交换两个字节位置意味着交换对应的 8 组 bit-slice word。

```
Row 1 (字节 1,5,9,13) 左移 1 → 交换 3 组 8-word：
    swap_bits(1*8..1*8+7, 5*8..5*8+7)   // 1↔5
    swap_bits(5*8..5*8+7, 9*8..9*8+7)   // 5↔9 (原 1→5)
    swap_bits(9*8..9*8+7, 13*8..13*8+7) // 9↔13
    swap_bits(13*8..13*8+7, 原1的备份)    // 13↔1

Row 2 (字节 2,6,10,14) 左移 2 → 配对交换：
    swap_bits(2*8.., 10*8..)
    swap_bits(6*8.., 14*8..)

Row 3 (字节 3,7,11,15) 左移 3 (等价右移 1) → 类似 Row 1 的三次三角形交换
```

### 4.6 MixColumns 在 Bit-sliced 域中的实现

MixColumns 对每列 4 个字节进行 GF(2⁸) 矩阵乘法：

```
[s₀']   [2 3 1 1] [s₀]
[s₁'] = [1 2 3 1] [s₁]
[s₂']   [1 1 2 3] [s₂]
[s₃']   [3 1 1 2] [s₃]
```

**xtime 的 bit-sliced 实现**：在 GF(2⁸) 中乘以 x 可通过 bit 间的线性变换完成。对于字节的 8 个 bit 位置 b₇b₆...b₀：

```
xt₀ = b₇
xt₁ = b₀ ⊕ b₇
xt₂ = b₁
xt₃ = b₂ ⊕ b₇          (多项式 x⁸+x⁴+x³+x+1 → 反馈位为 x⁴+x³+x+1)
xt₄ = b₃ ⊕ b₇
xt₅ = b₄
xt₆ = b₅
xt₇ = b₆
```

然后组装新列值：
```
s₀' = xt(s₀) ⊕ (s₁ ⊕ xt(s₁)) ⊕ s₂ ⊕ s₃    // 2·s₀ ⊕ 3·s₁ ⊕ 1·s₂ ⊕ 1·s₃
s₁' = s₀ ⊕ xt(s₁) ⊕ (s₂ ⊕ xt(s₂)) ⊕ s₃
s₂' = s₀ ⊕ s₁ ⊕ xt(s₂) ⊕ (s₃ ⊕ xt(s₃))
s₃' = (s₀ ⊕ xt(s₀)) ⊕ s₁ ⊕ s₂ ⊕ xt(s₃)   // 3·s₀ ⊕ 1·s₁ ⊕ 1·s₂ ⊕ 2·s₃
```

### 4.7 AddRoundKey 在 Bit-sliced 域中的实现

轮密钥的 16 字节应用于所有 8 个块，通过按位翻转 bit-slice word 实现：

```cpp
for byte_idx = 0..15:
    k = key[byte_idx]
    for bit = 0..7:
        if (k >> bit) & 1:
            state.bits[byte_idx*8 + bit] ^= 0xFF  // 翻转所有 8 个块的该 bit
```

### 4.8 完整的 Bit-sliced 加密流程

```
encrypt_blocks:
    state = pack(8 个 16 字节块)
    
    add_round_key(state, round_keys[0])
    
    for round = 1..9:
        sub_bytes(state)       // bit-sliced S-box
        shift_rows(state)      // bit-sliced 行移位
        mix_columns(state)     // bit-sliced 列混合
        add_round_key(state, round_keys[round])
    
    sub_bytes(state)           // 最后一轮
    shift_rows(state)          // 无 MixColumns
    add_round_key(state, round_keys[10])
    
    unpack(state → 8 个块)
```

---

## 5. AES-128 密码核心

### 5.1 密钥扩展 (`expand_key`)

AES-128 密钥扩展将 16 字节密钥扩展为 11 个轮密钥（共 176 字节）。

**算法**：
```
w[0..3] = key                              // 前 4 个字 = 原始密钥
for i = 4..43:
    temp = w[i-1]
    if i % 4 == 0:
        temp = SubWord(RotWord(temp)) ⊕ Rcon[i/4]
    w[i] = w[i-4] ⊕ temp
```

**关键细节**：
- RotWord：`[a₀,a₁,a₂,a₃] → [a₁,a₂,a₃,a₀]`
- SubWord：对每个字节应用 S-box
- Rcon：`[x^(i/4-1), 0, 0, 0]`，其中 x 的幂在 GF(2⁸) 中计算

使用代数 S-box (`gf::sbox`) 而非查表，保证密钥扩展也是常数时间的。

### 5.2 标量路径（单块加密/解密）

标准 AES 实现，每轮依次执行 SubBytes → ShiftRows → MixColumns → AddRoundKey（最后一轮无 MixColumns）。所有子变换均使用代数 GF 运算，无查表。

**NIST 测试向量验证**：
- 明文：`32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34`
- 密钥：`2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c`
- 密文：`39 25 84 1d 02 dc 09 fb dc 11 85 97 19 6a 0b 32`
- **结果**：✓ 通过

### 5.3 Bit-sliced 路径 (`encrypt_bitsliced`)

批量加密任意数量的块：
1. 将块分组为 SLICE_WIDTH=8 的切片
2. 完整切片使用 `bitslice::encrypt_blocks`（bit-sliced 全轮）
3. 剩余不足 8 的块使用标量路径

```cpp
void encrypt_bitsliced(uint8_t* blocks, size_t count, key) {
    auto rk = expand_key(key);
    size_t full_slices = count / 8;
    for s in 0..full_slices:
        bitslice::encrypt_blocks(blocks + s*8*16, rk)
    for remaining:
        encrypt_block(scalar)  // 标量后备
}
```

### 5.4 快速路径 (`encrypt_fast`)

运行时选择最优路径的调度入口：

```
encrypt_fast:
    if AES-NI available:
        aesni::encrypt_blocks()    // 硬件加速
    else:
        encrypt_bitsliced()        // bit-sliced 软件
```

当前默认使用 bit-sliced 路径；AES-NI 路径在编译时检测 `__AES__` 宏。

---

## 6. 密码工作模式：CTR 与 GCM

### 6.1 CTR 模式

**原理**：将分组密码转换为流密码。

```
keystream[i] = AES_K(nonce || counter[i])
ciphertext[i] = plaintext[i] ⊕ keystream[i]
```

其中 `counter[i] = i`（从 0 开始递增的 32 位大端整数）。

**关键实现细节 — 分块计数器的正确性**：

初版实现存在一个严重 Bug：每消费完一个 keystream 块就递增计数器。在分块处理时，这会导致计数器错位。

**错误示例**（已修复）：
```
chunk 1 (50 bytes): 计数器 0→1→2→3 (最后一块只用2字节，但计数器仍递增到4)
chunk 2 (50 bytes): 计数器 4→5→6→7

解密 (100 bytes):   计数器 0→1→2→3→4→5→6
结果：字节 50 在加密时使用 counter[4]，解密时使用 counter[3] → 解密失败！
```

**正确方案**：从绝对字节位置计算计数器，而非依赖增量：

```cpp
uint64_t abs_pos = bytes_processed_ + offset;
size_t block_num = abs_pos / 16;
size_t byte_in_block = abs_pos % 16;
set_counter(block_num);
```

这样无论数据如何分块，字节位置 N 始终使用 keystream[N mod 16] 和 counter[N/16]。

### 6.2 GCM 模式

GCM (Galois/Counter Mode) 提供认证加密，结合 CTR 加密与 GHASH 认证。

#### 6.2.1 GHASH 认证

GHASH 是基于 GF(2¹²⁸) 的 MAC 算法：

```
H = AES_K(0¹²⁸)      // hash 子密钥
X₀ = 0
Xᵢ = (Xᵢ₋₁ ⊕ Cᵢ) · H  // 在 GF(2¹²⁸) 中
tag = Xₙ ⊕ E_K(J₀)
```

**GF(2¹²⁸) 乘法**：不可约多项式为 x¹²⁸ + x⁷ + x² + x + 1。

GF128 元素用两个 `uint64_t` 存储：

```cpp
struct GF128 { uint64_t hi, lo; };
```

乘法函数 `gf128_mul` 使用标准移位加法：
- 128 次迭代，常数时间
- 每次检查 b 的 LSB，条件性地将 v 异或到结果
- 然后将 v 乘以 x（左移 + 条件模约简）
- GCM 的约简多项式在低位：`R = 0xE1 << 56`

#### 6.2.2 GCM 加密流程

```
1. H = AES_K(0x00...0)     hash 子密钥
2. J₀ = nonce || 0³¹ || 1  初始计数器块
3. C = CTR_K(plaintext)     CTR 加密（计数器从 J₀+1 开始）
4. S = GHASH_H(A, C, len)   GHASH 计算
5. T = S ⊕ E_K(J₀)          认证标签
```

**验证**：GCM 加密+解密往返测试通过，认证标签 16 字节正确生成。

---

## 7. 流式处理框架

### 7.1 StreamProcessor 接口

```cpp
class StreamProcessor {
    virtual void process(std::span<uint8_t> data) = 0;  // 就地处理
    virtual void finish() = 0;                           // 结束流
    virtual std::span<const uint8_t> tag() const = 0;    // GCM 认证标签
    virtual uint64_t bytes_processed() const = 0;        // 已处理字节数
    static unique_ptr<StreamProcessor> create(algo, mode, key, nonce, encrypt);
};
```

**设计要点**：
- `process()` 接受 `std::span<uint8_t>` 实现零拷贝就地加密
- CTR 模式加密与解密是同一操作，`create()` 的 `encrypt` 参数在 CTR 模式下不影响行为
- 支持任意大小、任意次数的 `process()` 调用（分块无关性）

### 7.2 CtrStreamProcessor 实现

```cpp
void process(std::span<uint8_t> data) {
    for each data chunk:
        abs_pos = total_processed + offset
        counter = set_counter(abs_pos / 16)
        keystream = AES(counter)
        chunk_size = min(16 - abs_pos%16, remaining)
        XOR keystream[abs_pos%16 .. abs_pos%16+chunk_size-1] with data
        offset += chunk_size
}
```

### 7.3 FilePipeline

大文件加解密的零拷贝管道：

```cpp
class FilePipeline {
    uint64_t encrypt_file(input_path, output_path, config);
    uint64_t decrypt_file(input_path, output_path, config);
    void on_progress(fn);  // 进度回调 void(uint64_t done, uint64_t total)
};

struct PipelineConfig {
    size_t chunk_size = 1 << 20;  // 默认 1 MiB I/O 块
    bool parallel = false;        // 多线程（CTR 模式可并行）
    unsigned threads = 0;
    ProgressFn on_progress;
};
```

**数据流**：
```
文件 → 256 KiB 读取缓冲 → StreamProcessor::process() → 256 KiB 写入缓冲 → 输出文件
        ↑ 零拷贝直接操作                                  ↑ 原地修改后写出
```

---

## 8. SIMD 硬件加速层

### 8.1 架构抽象

```cpp
// 平台无关的向量类型
struct alignas(16) Vec128 { uint8_t data[16]; };
struct alignas(32) Vec256 { uint8_t data[32]; };

// 运算接口
Vec128 xor128(a, b);        // 128-bit 按位异或
Vec128 gf_mul128(a, b);     // 通道 GF(2⁸) 乘法
Vec256 xor256(a, b);        // 256-bit 按位异或 (AVX2)
```

### 8.2 条件编译路径

每个函数根据编译器宏选择最优实现：

```cpp
Vec128 xor128(const Vec128& a, const Vec128& b) {
#ifdef __SSE4_1__
    __m128i va = _mm_loadu_si128(&a);
    __m128i vb = _mm_loadu_si128(&b);
    __m128i vr = _mm_xor_si128(va, vb);      // 单条 SSE 指令
    Vec128 r;
    _mm_storeu_si128(&r, vr);
    return r;
#else
    Vec128 r;
    for (int i = 0; i < 16; ++i) r.data[i] = a.data[i] ^ b.data[i];  // 标量回退
    return r;
#endif
}
```

### 8.3 AES-NI 指令封装

```cpp
namespace simd::aesni {
    Vec128 enc_round(state, rk);        // _mm_aesenc_si128   — 1 轮加密
    Vec128 enc_round_last(state, rk);   // _mm_aesenclast_si128 — 末轮加密
    Vec128 dec_round(state, rk);        // _mm_aesdec_si128   — 1 轮解密
    void expand_key_128(key, rk_buf);   // _mm_aeskeygenassist_si128 — 密钥扩展
    void encrypt_blocks(blocks, n, rk); // 批量 AES-NI 加密
}
```

**关键实现细节 — AESKEYGENASSIST 的立即数约束**：

`_mm_aeskeygenassist_si128(k, rcon)` 的第二个参数必须是编译期 8 位立即数，不能是变量。因此使用 `switch` 展开 10 轮：

```cpp
for (int round = 0; round < 10; ++round) {
    int rcon;
    switch (round) {
        case 0: rcon = 0x01; break;
        ...
        case 9: rcon = 0x36; break;
    }
    __m128i tmp = _mm_aeskeygenassist_si128(k, rcon);
    ...
}
```

---

## 9. 内存管理子系统

### 9.1 SlabPool 固定大小分配器

```cpp
template<size_t BlockSize, size_t BlockCount = 1024>
class SlabPool {
    // 预分配 BlockSize × BlockCount 字节的连续内存池
    alignas(64) uint8_t pool_[BlockSize * BlockCount];
    
    // 空闲链表（嵌入在空闲块内部）
    struct Node { Node* next; };
    Node* free_list_;
};
```

**工作原理**：
- 构造时将所有块链入空闲链表（O(BlockCount) 一次性初始化）
- `alloc()` 从链表头部取一个块（O(1)）
- `dealloc()` 将块插回链表头部（O(1)）
- 完全避免 `malloc`/`free` 的每次调用开销与内存碎片

**预定义池**：
```cpp
using AESBlockPool   = SlabPool<16, 16384>;   // 256 KiB, 16384 个 AES 块
using CtxBufferPool  = SlabPool<64, 4096>;    // 256 KiB, 4096 个上下文缓冲
using SIMDBufferPool = SlabPool<32, 8192>;    // 256 KiB, 8192 个 SIMD 缓冲
```

### 9.2 std::span 工具函数

```cpp
// 对齐检查
bool is_aligned(span, alignment);

// 跨度切片
auto [left, right] = split_at(span, offset);
auto [taken, rest]  = take(span, n);

// 分块迭代器
Chunker chunker(data, chunk_size);
while (auto chunk = chunker.next()) { ... }
```

---

## 10. 关键实现决策与调试记录

### 10.1 S-box 仿射变换的旋转方向 Bug

**问题**：初始实现使用 `std::rotl`（左旋）来实现仿射变换：

```cpp
// 错误：bit i 得到 rotl(a, k) 的位置 i = a₍ᵢ₋ₖ₎ 而非 a₍ᵢ₊ₖ₎
result ^= std::rotl(a, 4);  // 错误！
```

**分析**：AES 仿射变换需要 `a₍ᵢ₊₄₎`，即 bit i 应该取 a 的 bit (i+4) mod 8。`rotl(a, 4)` 在 bit i 得到的是 `a₍ᵢ₋₄₎`，恰好相反。

**修复**：将 `std::rotl` 替换为 `std::rotr`。

### 10.2 逆仿射变换的额外项 Bug

**问题**：逆仿射变换公式为 `bᵢ' = a₍ᵢ₊₂₎ ⊕ a₍ᵢ₊₅₎ ⊕ a₍ᵢ₊₇₎ ⊕ dᵢ`，不含 `aᵢ` 项。初版错误地包含了 `aᵢ`：

```cpp
GF8 x = a;                         // 错误：包含了 a 自身
x ^= std::rotr(a, 2);
x ^= std::rotr(a, 5);
x ^= std::rotr(a, 7);
```

**修复**：去掉 `GF8 x = a;`，直接以各旋转结果异或作为初值。

### 10.3 Bit-sliced Pack/Unpack 字节序 Bug

**问题**：pack 函数使用 `byte_idx = 15 - (bit / 8)` 的逆序字节布局，但所有轮操作（AddRoundKey、ShiftRows 等）假设正序字节布局。

**表现**：AddRoundKey 将 `key[0]` 错误地应用到逻辑字节 15 而非字节 0。

**修复**：将 pack/unpack 改为 `byte_idx = bit / 8` 正序字节布局。

### 10.4 CTR 分块计数器 Bug

**问题**：CtrStreamProcessor 按每块 16 字节递增计数器，但不考虑跨 `process()` 调用的块对齐。

**表现**：分块加密后解密失败（memcmp 返回非零）。

**修复**：从绝对字节位置 `bytes_processed_ + offset` 计算 `block_num = abs_pos / 16` 和 `byte_in_block = abs_pos % 16`，确保位置无关的计数器语义。

### 10.5 ODR 违规：SliceWord 大小不一致

**问题**：库编译时定义了 `STREAMCIPHER_SIMD`，`SliceWord = uint64_t` (8 bytes)，`BitSliceState = 1024 bytes`。测试编译时未定义，`SliceWord = uint8_t` (1 byte)，`BitSliceState = 128 bytes`。

**表现**：栈溢出（stack smashing detected）+ AddressSanitizer 检测到 1024 字节写入 128 字节栈变量。

**修复**：固定 `SliceWord = uint8_t`，不依赖编译宏。SIMD 加宽在内部处理。

### 10.6 AESKEYGENASSIST 立即数约束

**问题**：`_mm_aeskeygenassist_si128` 要求第二个参数为编译期 8 位立即数，传入数组元素或变量会编译失败。

**修复**：使用 `switch` 将 10 个 Rcon 值展开为编译期常量。

---

## 11. 测试策略与覆盖度

### 11.1 测试框架

使用 Catch2 v3.7.1，4 个测试可执行文件，覆盖全部模块。

### 11.2 测试覆盖矩阵

| 测试文件 | 测试用例数 | 断言数 | 覆盖内容 |
|----------|-----------|--------|----------|
| `test_gf` | 12 | 67,581 | GF(2⁸) 乘法恒等/交换/结合/分配律、xtime、逆元全表验证、S-box 标准值、往返、mul3/9/11/13/14、批量运算 |
| `test_aes` | 7 | 17+ | 密钥扩展、NIST 加密向量、NIST 解密向量、标量往返、bit-sliced 批量加密、bit-sliced 批量解密、encrypt_fast |
| `test_stream` | 5 | 18 | CTR 小块往返、CTR 分块流式 API、CTR 跨 16 字节边界、GCM 往返、GCM 流式 API |
| `test_simd` | 4 | 8 | Vec128 XOR、load/store 往返、shift_bytes_left、CPU 特性检测 |

### 11.3 测试运行

```
$ ctest --test-dir build
100% tests passed, 0 tests failed out of 4
```

---

## 12. 性能分析框架

### 12.1 基准测试

使用 Google Benchmark v1.9.1：

| 基准 | 测量目标 |
|------|----------|
| `bench_gf` | GF(2⁸) 单次乘法/逆元 vs 批量 1K 运算 |
| `bench_aes` | 密钥扩展、单块标量加密、bit-sliced 8 块批量、encrypt_fast 64 KiB |
| `bench_stream` | CTR 1 MiB 流式处理、CTR 1 MiB one-shot、GCM 1 MiB one-shot |

### 12.2 CLI 内置基准

```bash
$ ./build/apps/scipher benchmark
Running CTR benchmark: 1 MiB x 10 iterations
Total: 10 MiB in X ms
Throughput: Y MiB/s
```

### 12.3 预期性能特征

- **标量路径**：~100-200 MB/s（取决于 CPU 频率和编译器优化）
- **Bit-sliced 路径**（8 块并行）：理论提升 2-3× 于标量路径
- **AES-NI 路径**：理论达到 ~3-5 GB/s（受内存带宽限制）

（实际数值需要 `cmake -DSTREAMCIPHER_BUILD_BENCHMARKS=ON` 后运行 `scripts/benchmark.sh` 获取）

---

## 附录 A：参考文献

1. Käsper, E., & Schwabe, P. (2009). "Faster and Timing-Attack Resistant AES-GCM." CHES 2009.
2. Canright, D. (2005). "A Very Compact S-box for AES." CHES 2005.
3. NIST FIPS 197. "Advanced Encryption Standard (AES)." 2001.
4. NIST SP 800-38D. "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)." 2007.
5. Intel. "Intel Advanced Encryption Standard Instructions (AES-NI)." 2010.

## 附录 B：编译与运行

```bash
# 完整构建（含测试和基准）
cmake -B build -DCMAKE_BUILD_TYPE=Release \
    -DSTREAMCIPHER_BUILD_TESTS=ON \
    -DSTREAMCIPHER_BUILD_BENCHMARKS=ON \
    -DSTREAMCIPHER_BUILD_EXAMPLES=ON \
    -DSTREAMCIPHER_BUILD_APPS=ON
cmake --build build -j$(nproc)

# 运行测试
ctest --test-dir build

# 运行基准
./build/benchmarks/bench_aes
./build/benchmarks/bench_stream

# CLI 工具
./build/apps/scipher encrypt input.txt output.enc
./build/apps/scipher decrypt output.enc recovered.txt
./build/apps/scipher benchmark
```
