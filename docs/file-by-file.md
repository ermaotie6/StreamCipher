# StreamCipher 逐文件详解

> 本文档对项目中的每一个文件进行详细解释，包括其设计意图、
> 内部结构、关键实现决策、与其他文件的关联，以及任何值得注意的细节。
> 适合初次阅读源码或需要对项目进行深入理解的开发者。

---

## 目录

- [一、项目根目录文件](#一根目录文件)
- [二、CMake 构建系统](#二cmake-构建系统)
- [三、公共头文件 include/streamcipher/](#三公共头文件-includestreamcipher)
  - [3.1 伞形头文件](#31-伞形头文件)
  - [3.2 密码核心 core/](#32-密码核心-core)
  - [3.3 流式处理 stream/](#33-流式处理-stream)
  - [3.4 硬件加速 simd/](#34-硬件加速-simd)
  - [3.5 内存管理 memory/](#35-内存管理-memory)
- [四、实现文件 src/](#四实现文件-src)
  - [4.1 密码核心 src/core/](#41-密码核心-srccore)
  - [4.2 流式处理 src/stream/](#42-流式处理-srcstream)
  - [4.3 硬件加速 src/simd/](#43-硬件加速-srcsimd)
  - [4.4 内存管理 src/memory/](#44-内存管理-srcmemory)
- [五、测试文件 tests/](#五测试文件-tests)
- [六、基准测试 benchmarks/](#六基准测试-benchmarks)
- [七、示例 examples/](#七示例-examples)
- [八、命令行工具 apps/](#八命令行工具-apps)
- [九、文档 docs/](#九文档-docs)
- [十、脚本 scripts/](#十脚本-scripts)

---

## 一、根目录文件

### `.gitignore`

标准的 C++ 项目忽略规则。排除了 `build/` 构建目录、IDE 配置文件、编译产物（`.o`/`.a`/`.so`）、CMake 缓存、以及 OS 垃圾文件（`.DS_Store`、`Thumbs.db`）。

### `LICENSE`

MIT 许可证。选择 MIT 是为了最大化开源使用自由度，符合申报书中"开源高性能 C++ 加密库"的定位。

### `README.md`

项目的门面文档，包含：项目概述、四大核心创新点、完整的文件树（39 个文件）、架构分层图、CTR 数据流图、NIST 测试向量验证结果、快速开始指南、API 使用示例、交付成果清单、后续工作计划。面向答辩和评审场景编写。

---

## 二、CMake 构建系统

### `CMakeLists.txt`（顶层）

**作用**：整个项目的构建入口。

**关键配置**：

```
cmake_minimum_required(VERSION 3.20)
project(streamcipher VERSION 0.1.0 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
```

- C++20 是硬性要求（需要 `std::span`、`constexpr` 增强、`<bit>` 头等）
- 提供 5 个构建选项：`STREAMCIPHER_BUILD_TESTS`、`_BENCHMARKS`、`_EXAMPLES`、`_APPS`、`_USE_SIMD`、`_USE_AESNI`
- SIMD 选项开启时自动追加 `-maes -msse4.1 -mavx2` 编译标志
- 定义 `STREAMCIPHER_SIMD` 和 `STREAMCIPHER_AESNI` 预处理宏
- 安装规则将库和头文件安装到标准位置
- 通过 `add_subdirectory` 引入 tests/benchmarks/examples/apps 四个子目录

**设计决策**：tests 和 benchmarks 的第三方依赖（Catch2、Google Benchmark）通过 `FetchContent` 自动下载，不要求用户手动安装。这降低了构建门槛，但首次 configure 需要联网。

### `cmake/DetectArch.cmake`

**作用**：检测目标 CPU 架构，据此决定是否启用 AES-NI。

**逻辑**：
- 通过 `CMAKE_SYSTEM_PROCESSOR` 匹配 `x86_64` / `aarch64` / 其他
- 非 x86_64 架构自动禁用 AES-NI
- 设置 `STREAMCIPHER_ARCH` 变量供其他模块使用

---

## 三、公共头文件 `include/streamcipher/`

### 3.1 伞形头文件

#### `streamcipher.hpp`

**作用**：用户只需 `#include "streamcipher/streamcipher.hpp"` 即可引入所有公开 API。

**内容**：按层次顺序包含 9 个子头文件：
1. `core/gf.hpp`、`bitslice.hpp`、`aes.hpp`、`cipher.hpp` — 密码核心
2. `stream/stream.hpp`、`pipeline.hpp` — 流式处理
3. `simd/simd.hpp`、`aesni.hpp` — 硬件加速
4. `memory/pool.hpp`、`span_utils.hpp` — 内存管理

使用 `#pragma once` 防止重复包含。

---

### 3.2 密码核心 `core/`

#### `gf.hpp` — Galois Field GF(2⁸) 纯位运算

**作用**：定义 GF(2⁸) 的所有基本运算，是项目最底层的数学基础。全部 `constexpr`，编译器可完全内联。

**关键内容**：

| 符号 | 行数 | 说明 |
|------|------|------|
| `IRREDUCIBLE_POLY = 0x1B` | ~19 | x⁸+x⁴+x³+x+1，AES 标准不可约多项式 |
| `GF8 = uint8_t` | ~22 | GF(2⁸) 元素类型 |
| `mul(a,b)` | 28-38 | 移位加法，固定 8 迭代，`&-(b&1)` 无分支条件异或 |
| `inv(a)` | 42-54 | 费马小定理 a^254，二进制快速幂 |
| `xtime(a)` | 58-60 | 乘 x 特化，MixColumns 专用 |
| `mul3/9/11/13/14` | 63-85 | 逆 MixColumns 系数，xtime 叠加 |
| `sbox(a)` | 90-103 | 代数 S-box：gf_inv → rotr 仿射 |
| `inv_sbox(a)` | 108-111 | 逆 S-box：rotr 逆仿射 → gf_inv |
| `mul_batch/inv_batch/sbox_batch` | 117-130 | 批量运算声明（实现在 gf.cpp） |

**S-box 实现细节**：

仿射变换 `b_i = a_i ⊕ a_{i+4} ⊕ a_{i+5} ⊕ a_{i+6} ⊕ a_{i+7} ⊕ c_i` 通过 `std::rotr` 实现。关键是**右旋不是左旋**——初版用 `rotl` 导致 S-box 输出全错，花了很长时间调试才发现。逆 S-box 的逆仿射公式不含 a_i 项（与正向不同），这是另一个踩过的坑。

**验证**：NIST 标准 S-box 值全部通过。`sbox(0x00)=0x63`, `sbox(0x53)=0xED`, `sbox(0xFF)=0x16`。全表往返 `inv_sbox(sbox(x))==x` 对 256 个值成立。

#### `bitslice.hpp` — 位切片数据结构与接口

**作用**：定义 bit-sliced AES 的核心数据结构和所有轮操作接口。

**关键内容**：

| 符号 | 说明 |
|------|------|
| `SLICE_WIDTH = 8` | 一次处理 8 个 AES 块 |
| `SLICE_BYTES = 128` | 8×16 字节 |
| `SliceWord = uint8_t` | 一个 bit-slice word 存 8 个块的同一位 |
| `BitSliceState` | `alignas(64)` 的 128 字节结构，128 个 SliceWord |
| `pack/unpack` | 字节块 ↔ bit-slice 状态转换 |
| `sub_bytes/inv_sub_bytes` | bit-sliced SubBytes |
| `shift_rows/inv_shift_rows` | bit-sliced ShiftRows |
| `mix_columns/inv_mix_columns` | bit-sliced MixColumns |
| `add_round_key` | bit-sliced AddRoundKey |
| `encrypt_blocks/decrypt_blocks` | 完整 bit-sliced 加密/解密（各 10+1 轮） |

**ABI 稳定性**：`SliceWord` 固定为 `uint8_t`，不依赖 `STREAMCIPHER_SIMD` 宏。此前曾根据宏切换为 `uint64_t`，导致库与测试代码的 `BitSliceState` 大小不一致（1024 vs 128 字节），触发栈溢出和 ODR 违规。

#### `aes.hpp` — AES-128 API

**作用**：AES-128 加密解密的公开接口。

**关键内容**：

| 类型/函数 | 说明 |
|-----------|------|
| `BLOCK_SIZE=16, KEY_SIZE=16, ROUNDS=10` | AES-128 常量 |
| `RoundKeys = array<array<uint8_t,16>, 11>` | 11 个轮密钥 |
| `expand_key(key)` | 密钥扩展 |
| `encrypt_block / decrypt_block` | 标量单块加解密 |
| `encrypt_ecb / decrypt_ecb` | ECB 便捷封装（带密钥扩展） |
| `encrypt_bitsliced(blocks, count, key)` | bit-sliced 批量加密 |
| `encrypt_fast(blocks, count, key)` | 快速路径（AES-NI → bit-sliced → 标量） |
| `has_aesni()` | AES-NI 可用性检测 |

#### `cipher.hpp` — 密码模式抽象

**作用**：定义密码模式的统一接口，支持 CTR、GCM、ECB 三种模式。

**关键内容**：

| 类型 | 说明 |
|------|------|
| `enum Algorithm { AES_128 }` | 支持的密码算法（可扩展） |
| `enum Mode { ECB, CTR, GCM }` | 支持的工作模式 |
| `class CipherCtx` | 抽象密码上下文：`update()`, `finalize()`, `tag()` |
| `create(algo, mode, key, nonce)` | 工厂函数，返回 `unique_ptr<CipherCtx>` |

`CipherCtx` 使用虚函数实现多态，非拷贝但可移动。工厂函数根据 `mode` 参数创建对应的 `CtrCipherCtx` 或 `GcmCipherCtx` 实例。

---

### 3.3 流式处理 `stream/`

#### `stream.hpp` — StreamProcessor 接口

**作用**：流式加解密的高层抽象。

**关键内容**：

| 类型 | 说明 |
|------|------|
| `class StreamProcessor` | 抽象流处理器：`process(span<uint8_t>)`, `finish()`, `tag()`, `bytes_processed()` |
| `create(algo, mode, key, nonce, encrypt)` | 工厂函数 |
| `encrypt_one_shot(...)` | 一次性加密便捷函数 |
| `decrypt_one_shot(...)` | 一次性解密便捷函数 |

设计关键：`process()` 接受 `std::span<uint8_t>` 实现零拷贝原地操作。CTR 模式下加密和解密是同一操作（密钥流异或），因此 `encrypt` 参数在 CTR 模式下不影响行为。

#### `pipeline.hpp` — 文件管道

**作用**：文件级加解密的编排器。

**关键内容**：

| 类型 | 说明 |
|------|------|
| `struct PipelineConfig` | 配置：`chunk_size`、`parallel`、`threads`、`on_progress` |
| `class FilePipeline` | PIMPL 模式，`encrypt_file()` / `decrypt_file()` |

`PipelineConfig::on_progress` 是 `function<void(uint64_t done, uint64_t total)>` 类型的进度回调，在每处理完一个 I/O 块后调用。

---

### 3.4 硬件加速 `simd/`

#### `simd.hpp` — SIMD 向量抽象

**作用**：定义架构无关的 128/256 位向量类型和操作。

**关键内容**：

| 类型/函数 | 说明 |
|-----------|------|
| `Vec128 (alignas(16))` | 128 位向量 |
| `Vec256 (alignas(32))` | 256 位向量（需 `STREAMCIPHER_SIMD`） |
| `xor128/xor256` | 按位异或（SSE4.1/AVX2 加速） |
| `gf_mul128/gf_mul256` | 通道 GF(2⁸) 乘法 |
| `load128/store128` | 非对齐加载/存储 |
| `has_sse41/has_avx2/has_aesni` | CPU 特性检测 |

每个函数都有条件编译路径：`__SSE4_1__` / `__AVX2__` 宏定义时使用内联 SIMD 指令，否则走标量循环回退。

#### `aesni.hpp` — AES-NI 指令封装

**作用**：封装 x86 AES-NI 新指令。

**关键内容**：

| 函数 | 对应指令 |
|------|----------|
| `enc_round` | `_mm_aesenc_si128` |
| `enc_round_last` | `_mm_aesenclast_si128` |
| `dec_round` | `_mm_aesdec_si128` |
| `dec_round_last` | `_mm_aesdeclast_si128` |
| `expand_key_128` | `_mm_aeskeygenassist_si128` |
| `encrypt_blocks/decrypt_blocks` | 批量加密/解密 |

仅在 `STREAMCIPHER_AESNI` 宏定义时编译硬件路径，否则所有函数回退到软件实现。

---

### 3.5 内存管理 `memory/`

#### `pool.hpp` — SlabPool 固定大小分配器

**作用**：header-only 的模板类，预分配连续内存池，O(1) 分配/释放。

**关键设计**：

```
template<size_t BlockSize, size_t BlockCount = 1024>
class SlabPool {
    alignas(64) uint8_t pool_[BlockSize * BlockCount];
    struct Node { Node* next; };
    Node* free_list_;
    size_t used_;
};
```

- 构造时将所有块链入 `free_list_`（单向链表，节点嵌入空闲块内部）
- `alloc()` 从链表头取一块（O(1)）
- `dealloc()` 将块插回链表头（O(1)）
- 池耗尽时 `alloc()` 返回 `nullptr`（不抛异常，noexcept 保证）

**预定义别名**：
- `AESBlockPool = SlabPool<16, 16384>` — 256 KiB，存 16384 个 AES 块
- `CtxBufferPool = SlabPool<64, 4096>` — 256 KiB
- `SIMDBufferPool = SlabPool<32, 8192>` — 256 KiB

#### `span_utils.hpp` — std::span 工具函数

**作用**：header-only 的辅助工具，简化 span 操作。

**关键内容**：
- `is_aligned(span, alignment)` — 检查起始地址对齐
- `align_offset(span, alignment)` — 计算对齐所需跳过的字节数
- `split_at(span, offset)` — 在 offset 处一分为二
- `take(span, n)` — 取前 n 个元素，返回 `(已取, 剩余)`
- `class Chunker` — 固定大小分块迭代器

---

## 四、实现文件 `src/`

### 4.1 密码核心 `src/core/`

#### `gf.cpp` — GF(2⁸) 批量运算

**内容**：`mul_batch`、`inv_batch`、`sbox_batch`、`inv_sbox_batch` 四个批量函数的实现。每个都是简单的 for 循环调用对应的 `constexpr` 标量函数。编译器对这些循环的自动向量化效果不错，不需要手写 SIMD。

#### `bitslice.cpp` — 位切片 AES 完整实现（~496 行）

**这是项目最核心、最复杂的实现文件。**

**结构概述**：

| 段落 | 行数 | 说明 |
|------|------|------|
| pack/unpack | ~27-57 | 字节块 ↔ bit-slice 状态转换 |
| 布尔运算 | ~63-85 | xor/and/not/or_state（给将来门电路用） |
| Canright S-box (#if 0) | ~108-338 | GF((2⁴)²) 组合域布尔电路（封印中） |
| SubBytes（标量路径） | ~343-425 | 提取→gf::sbox→注入 |
| ShiftRows | ~431-483 | 行移位的 bit-sliced 实现 |
| MixColumns | ~485-580 | 列混合的 bit-sliced 实现 |
| AddRoundKey | ~584-595 | 轮密钥加 |
| encrypt/decrypt_blocks | ~600-693 | 完整 10 轮加密/解密 |

**Pack/Unpack 详解**：

Pack 将 8 个 16 字节块转换为 128 个 SliceWord：
```
for bit in 0..127:
    byte_idx = bit / 8       // 逻辑字节 0..15
    bit_in_byte = bit % 8    // 字节内位 0..7
    word = 0
    for block in 0..7:
        if block[block][byte_idx] 的 bit_in_byte 位为 1:
            word |= (1 << block)
    state.bits[bit] = word
```

**ShiftRows 在 bit-sliced 域中的实现**：

因为 state.bits[byte_idx*8 .. byte_idx*8+7] 对应逻辑字节 byte_idx 的 8 个 bit，所以 ShiftRows 就是交换 8 个一组的 SliceWord：
- Row 1（字节 1,5,9,13）左移 1：三次三角形交换
- Row 2（字节 2,6,10,14）左移 2：两组配对交换
- Row 3（字节 3,7,11,15）左移 3（等价右移 1）：三角形交换

**MixColumns 的 xtime_slice**：

GF(2⁸) 中乘以 x 在 bit-sliced 域中是线性的：
```
xt0 = b7
xt1 = b0 ^ b7
xt2 = b1
xt3 = b2 ^ b7    (0x1B 反馈位)
xt4 = b3 ^ b7
xt5 = b4
xt6 = b5
xt7 = b6
```

然后组装列：
```
s0' = xt(s0) ⊕ s1 ⊕ xt(s1) ⊕ s2 ⊕ s3    // 2·s0 ⊕ 3·s1 ⊕ 1·s2 ⊕ 1·s3
s1' = s0 ⊕ xt(s1) ⊕ s2 ⊕ xt(s2) ⊕ s3
s2' = s0 ⊕ s1 ⊕ xt(s2) ⊕ s3 ⊕ xt(s3)
s3' = s0 ⊕ xt(s0) ⊕ s1 ⊕ s2 ⊕ xt(s3)    // 3·s0 ⊕ 1·s1 ⊕ 1·s2 ⊕ 2·s3
```

**AddRoundKey 详解**：

轮密钥的每个字节异或到所有 8 个块的对应字节。在 bit-sliced 域中：key 某 bit 为 1 → 翻转对应的整个 SliceWord（8 位全取反）：
```cpp
if ((k >> bit) & 1) state.bits[byte_idx*8 + bit] ^= 0xFF;
```

**#if 0 封印的 Canright 布尔电路**：

这是一套完整的 GF((2⁴)²) 组合域 S-box 实现，包含：
- `gf4_mul` — GF(2⁴) 乘法（约 12 个 AND + 若干 XOR）
- `gf4_sq` — GF(2⁴) 平方
- `gf4_inv` — GF(2⁴) 逆元（真值表化简）
- `gf4_mul_lambda` — 乘常数 λ=0x6
- `gf8c_inv` — GF((2⁴)²) 逆元
- `T_transform / T_inv_transform` — 同构映射的 4×8 矩阵
- `affine_transform` — 仿射变换
- `sbox_circuit / inv_sbox_circuit` — 完整的布尔电路 S-box

当前封印的原因是 **T_transform/T_inv_transform 的矩阵系数与 NIST 测试向量对不上**，怀疑是 λ 的取值或基的选择问题（Canright 论文里有不同的同构映射变体）。

#### `aes.cpp` — AES-128 三路实现（~187 行）

**结构**：
1. `expand_key()` — 密钥扩展（代数的 S-box，不查表）
2. 标量轮操作（匿名 namespace 内）：`sub_bytes_scalar`、`shift_rows_scalar`、`mix_columns_scalar`、`inv_mix_columns_scalar`、`add_round_key_scalar`
3. `encrypt_block / decrypt_block` — 完整 10 轮标量加密/解密
4. `encrypt_ecb / decrypt_ecb` — ECB 便捷封装
5. `encrypt_bitsliced()` — 批量加密调度：完整 8 块切片走 `bitslice::encrypt_blocks`，不足 8 块走标量
6. `encrypt_fast()` — 快速路径入口（当前默认走 bit-sliced）
7. `has_aesni()` — 编译时 AES-NI 检测

**MixColumns 标量实现**：

使用恒等式 `2a⊕3b⊕c⊕d = (a⊕b⊕c⊕d) ⊕ xtime(a⊕b) ⊕ a` 将 4 次 xtime 优化为 1 次 XOR+xtime，减少 GF(2⁸) 运算次数。

#### `cipher.cpp` — CTR 和 GCM 模式实现（~230 行）

**结构**：

1. **GHASH 子模块**（匿名 namespace）：
   - `GF128 {uint64_t hi, lo}` — GF(2¹²⁸) 元素
   - `gf128_mul(a, b)` — GF(2¹²⁸) 乘法（128 次迭代，常数时间）
   - 约简多项式 `R = 0xE1 << 56`（GCM bit-reflection 规定）
   - `bytes_to_gf128 / gf128_to_bytes` — 字节 ↔ GF128 转换（big-endian）

2. **CtrCipherCtx**：
   - 简单的计数器模式：nonce(12) || counter(4)，counter 大端递增
   - `update()` 逐个 keystream block 异或

3. **GcmCipherCtx**：
   - 初始化：`H = AES_K(0)` → `J0 = nonce||0³¹||1`
   - `update()`：CTR 加密 + GHASH 累加
   - counter 从绝对字节位置计算（关键设计，避免跨 `process()` 调用的分块对齐问题）
   - `finalize()`：追加 `len(A)||len(C)` 到 GHASH → tag = GHASH ⊕ E_K(J0)

**GCM Counter 的 +1 偏移**：GCM 规范中 counter 0 保留给 J0（初始计数器块），实际数据加密从 counter 1 开始。这是 `set_counter(block_num + 1)` 中 `+1` 的来源。

---

### 4.2 流式处理 `src/stream/`

#### `stream.cpp` — StreamProcessor 实现（~180 行）

**结构**：

1. **CtrStreamProcessor**：
   - 核心设计：从绝对字节位置 `bytes_processed_ + offset` 计算 `block_num = abs_pos / 16` 和 `byte_in_block = abs_pos % 16`
   - 这样无论数据如何分块，字节位置 N 始终使用 keystream[N mod 16]
   - 这是经历了一个严重 Bug 后的修复——初版使用简单递增 counter，导致跨 `process()` 调用的分块边界处 counter 错位，加密后无法解密

2. **GcmStreamProcessor**：
   - 包装 `cipher::GcmCipherCtx`（因为 cipher::update 不支持原地操作）
   - 使用 `thread_local std::vector<uint8_t>` 作为临时中转缓冲区

3. **工厂函数** `StreamProcessor::create()`

4. **便捷函数** `encrypt_one_shot / decrypt_one_shot`

#### `pipeline.cpp` — FilePipeline 实现（~143 行）

**结构**：

- PIMPL 模式：`FilePipeline::Impl` 持有 algo/mode/key/nonce/回调
- `encrypt_file()`：打开输入文件 → 创建 StreamProcessor → 256 KiB 循环读写 → GCM 追加 tag
- `decrypt_file()`：同上，GCM 模式下自动剥离最后 16 字节 tag
- 每处理完一个 I/O 块后调用 `on_progress` 回调

---

### 4.3 硬件加速 `src/simd/`

#### `simd.cpp` — SIMD 向量操作实现（~162 行）

每个函数都有 `#ifdef __SSE4_1__` / `#ifdef __AVX2__` 的条件编译路径。有硬件就用 `_mm_loadu_si128` / `_mm_xor_si128` 等内联函数，没有就走标量循环。

`gf_mul128` 和 `gf_mul256` 永远走标量循环（因为没有直接的 GF(2⁸) SIMD 乘法指令）。

#### `aesni.cpp` — AES-NI 指令实现（~144 行）

**结构**：

1. 单轮操作：`enc_round / enc_round_last / dec_round / dec_round_last`，有 AES-NI 用 `_mm_aesenc_si128` 等指令，没有就回退

2. `expand_key_128`：使用 `_mm_aeskeygenassist_si128` 做密钥扩展。**关键坑**：该指令的第二个参数必须是编译期 8 位立即数，不能传变量。因此用 `switch` 将 10 个 Rcon 值硬编码展开

3. `encrypt_blocks / decrypt_blocks`：加载 11 个轮密钥到 `__m128i rk[11]`，循环处理每个块

---

### 4.4 内存管理 `src/memory/`

#### `pool.cpp` / `span_utils.cpp`

两个文件都是占位实现（SlabPool 模板是 header-only，span 工具也是 header-only）。保留这两个 .cpp 文件是为了将来可能添加显式模板实例化或非模板辅助函数。

---

## 五、测试文件 `tests/`

### `CMakeLists.txt`

通过 FetchContent 获取 Catch2 v3.7.1，构建 4 个测试可执行文件并注册到 CTest。

### `test_gf.cpp` — GF(2⁸) 测试（12 用例，67581 断言）

**测试覆盖**：
- 乘法恒等性、交换律、结合律、分配律
- xtime 与 mul(·, 0x02) 的一致性（全 255 值）
- 逆元往返验证（全 255 个非零值：`mul(a, inv(a)) == 1`）
- S-box 标准值（0x00→0x63, 0x53→0xED, 0xFF→0x16）
- S-box 往返 `inv_sbox(sbox(x)) == x`（全 256 值）
- mul3/9/11/13/14 与通用乘法的等价性
- 批量函数与标量函数的一致性（256 元素）

### `test_aes.cpp` — AES-128 测试（7 用例）

**测试覆盖**：
- 密钥扩展（首轮密钥 = 原始密钥，末轮首字节 = 0xd0）
- NIST FIPS 197 标准加密向量
- NIST 标准解密向量
- 标量加解密往返
- Bit-sliced 批量加密 → 标量解密往返（验证 bit-sliced 正确性）
- `encrypt_fast` 批量往返

### `test_stream.cpp` — 流式加解密测试（5 用例）

**测试覆盖**：
- CTR 小块往返（256 字节 one-shot）
- CTR 分块流式 API（3 次不等大小的 process 调用）
- CTR 跨 16 字节边界（31 字节，非块对齐）
- GCM 往返（256 字节，含 16 字节 tag）
- GCM 流式 API（分块处理后解密验证）

第 3 个用例（跨边界）和第 2 个用例（分块）设计为专门验证 CTR counter 的正确性——修复 counter 错位 Bug 后这些测试才通过。

### `test_simd.cpp` — SIMD 测试（4 用例）

**测试覆盖**：
- Vec128 XOR 正确性
- load128/store128 往返
- shift_bytes_left 正确性
- CPU 特性检测（不崩溃即可）

---

## 六、基准测试 `benchmarks/`

### `CMakeLists.txt`

通过 FetchContent 获取 Google Benchmark v1.9.1，构建 3 个基准可执行文件。

### `bench_gf.cpp` — GF(2⁸) 性能基准

单次乘法/逆元 + 批量 1024 元素的乘法和逆元。用于对比标量循环的吞吐。

### `bench_aes.cpp` — AES-128 性能基准

- 密钥扩展延迟
- 单块标量加密/解密
- Bit-sliced 128 字节（8 块）吞吐
- 标量 128 字节吞吐（对照）
- encrypt_fast 64 KiB 吞吐

通过 `state.SetBytesProcessed()` 报告吞吐量。Sc alar vs Bit-sliced 的对比可以看出 bit-slicing 在批量场景下的加速比。

### `bench_stream.cpp` — 流式处理性能基准

- CTR 1 MiB 流式分块吞吐
- CTR 1 MiB one-shot 吞吐
- GCM 1 MiB one-shot 吞吐

---

## 七、示例 `examples/`

### `CMakeLists.txt`

构建 `encrypt_file` 和 `decrypt_file` 两个可执行文件，链接 `streamcipher` 库。

### `encrypt_file.cpp` — 文件加密示例

使用 `FilePipeline` 加密文件，展示：
- 固定测试密钥和 nonce（生产环境应使用 KDF）
- 1 MiB 分块配置
- 进度百分比回调
- 输出写入字节数

### `decrypt_file.cpp` — 文件解密示例

与 `encrypt_file.cpp` 对称，使用相同的密钥和 nonce 解密。

---

## 八、命令行工具 `apps/`

### `CMakeLists.txt`

构建 `scipher` 可执行文件。

### `main.cpp` — scipher CLI 工具（~194 行）

**支持的命令**：

1. `scipher encrypt <input> <output> [--mode ctr|gcm] [--key <hex>] [--nonce <hex>]`
2. `scipher decrypt <input> <output> [options]`
3. `scipher benchmark [--size <N>]`
4. `scipher --help`

**设计特点**：
- 默认使用内置测试密钥（NIST 标准向量密钥），方便快速试用
- 支持 `--key` 和 `--nonce` 的十六进制指定（32/24 个 hex 字符）
- `benchmark` 子命令内置简单基准（不依赖 Google Benchmark），运行 10 次 1 MiB CTR 加密并报告吞吐（MiB/s）
- 进度回调在终端输出百分比（`\r` 回车覆盖）

---

## 九、文档 `docs/`

### `architecture.md` — 架构设计（中文）

内容：设计原则、分层架构图、CTR 数据流图、Bit-slicing 原理、内存模型、执行路径调度、后续方向。

### `api.md` — API 参考（中文）

7 个命名空间的完整 API 文档，包含函数签名、参数说明、返回值、使用示例。

### `implementation.md` — 详细实现文档（中文，~858 行）

12 章节的深度实现文档，涵盖：
1. 项目背景与设计目标
2. 总体架构
3. 数学基础：GF(2⁸)
4. Bit-slicing 层
5. AES-128 密码核心
6. CTR 与 GCM 模式
7. 流式处理框架
8. SIMD 硬件加速层
9. 内存管理子系统
10. 关键实现决策与调试记录（6 个 Bug）
11. 测试策略与覆盖度
12. 性能分析框架

---

## 十、脚本 `scripts/`

### `build.sh` — 构建脚本

一键 configure + build，默认 Release 模式，`-j$(nproc)` 并行编译。构建完成后提示测试和基准的运行命令。

### `benchmark.sh` — 基准测试脚本

依次运行 `bench_gf`、`bench_aes`、`bench_stream` 三个 Google Benchmark 可执行文件，最后运行 `scipher benchmark` 的内置基准。

---

## 附录：文件依赖关系图

```
用户代码
  └── streamcipher.hpp（伞形头文件）
        ├── gf.hpp ────────────────────── 底层数学
        │     └── gf.cpp
        ├── bitslice.hpp ──────────────── bit-slicing 引擎
        │     ├── gf.hpp
        │     └── bitslice.cpp
        ├── aes.hpp ───────────────────── AES-128 入口
        │     ├── gf.hpp
        │     ├── bitslice.hpp
        │     └── aes.cpp
        ├── cipher.hpp ────────────────── 密码模式
        │     ├── aes.hpp
        │     └── cipher.cpp
        ├── stream/stream.hpp ─────────── 流式加解密
        │     ├── cipher.hpp
        │     └── stream.cpp
        ├── stream/pipeline.hpp ───────── 文件管道
        │     ├── stream.hpp
        │     └── pipeline.cpp
        ├── simd/simd.hpp ─────────────── SIMD 抽象
        │     └── simd.cpp
        ├── simd/aesni.hpp ────────────── AES-NI
        │     ├── simd.hpp
        │     ├── aes.hpp
        │     └── aesni.cpp
        └── memory/
              ├── pool.hpp（header-only）
              └── span_utils.hpp（header-only）
```
