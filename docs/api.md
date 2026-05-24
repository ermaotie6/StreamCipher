# StreamCipher API 参考

## 命名空间: `streamcipher::gf`

有限域 GF(2⁸) 运算 — 纯位运算，常数时间。

| 函数 | 签名 | 说明 |
|------|------|------|
| `mul` | `constexpr GF8 mul(GF8 a, GF8 b)` | 两 GF(2⁸) 元素乘法 |
| `inv` | `constexpr GF8 inv(GF8 a)` | 乘法逆元，基于费马小定理 a^254 |
| `xtime` | `constexpr GF8 xtime(GF8 a)` | 乘以 x（MixColumns 中使用） |
| `mul3` | `constexpr GF8 mul3(GF8 a)` | 乘以 0x03 = xtime(a) ⊕ a |
| `mul9` | `constexpr GF8 mul9(GF8 a)` | 乘以 0x09 |
| `mul11` | `constexpr GF8 mul11(GF8 a)` | 乘以 0x0b |
| `mul13` | `constexpr GF8 mul13(GF8 a)` | 乘以 0x0d |
| `mul14` | `constexpr GF8 mul14(GF8 a)` | 乘以 0x0e |
| `sbox` | `constexpr GF8 sbox(GF8 a)` | AES S-box：GF 逆元 + 仿射变换，无查表 |
| `inv_sbox` | `constexpr GF8 inv_sbox(GF8 a)` | 逆 S-box：逆仿射 + GF 逆元 |
| `mul_batch` | `void mul_batch(GF8* d, const GF8* a, const GF8* b, size_t n)` | 批量乘法 |
| `inv_batch` | `void inv_batch(GF8* d, const GF8* s, size_t n)` | 批量逆元 |
| `sbox_batch` | `void sbox_batch(GF8* d, const GF8* s, size_t n)` | 批量 S-box |
| `inv_sbox_batch` | `void inv_sbox_batch(GF8* d, const GF8* s, size_t n)` | 批量逆 S-box |

**常数**：`IRREDUCIBLE_POLY = 0x1B`（AES 不可约多项式 x⁸+x⁴+x³+x+1）

## 命名空间: `streamcipher::bitslice`

位切片 AES —— 以机器字级位运算并行处理多个块。

| 符号 | 说明 |
|------|------|
| `SLICE_WIDTH = 8` | 并行处理的块数 |
| `BLOCK_BYTES = 16` | 每块 128 位 |
| `SLICE_BYTES = SLICE_WIDTH × 16` | 一个切片的总字节数 (128) |
| `SliceWord = uint8_t` | 位切片字类型（每字存 8 个块的一个 bit） |
| `BitSliceState` | 128 个 SliceWord 的结构体，表示位切片化的 AES 状态 (`alignas(64)`) |
| `pack(src)` | 将 8 个字节块转换为位切片表示 |
| `unpack(state, dst)` | 将位切片表示恢复为字节块 |
| `xor_state(a, b)` / `and_state(a, b)` / `not_state(a)` / `or_state(a, b)` | 状态级布尔运算 |
| `sub_bytes(state)` | 位切片域 SubBytes |
| `inv_sub_bytes(state)` | 位切片域逆 SubBytes |
| `shift_rows(state)` | 位切片域 ShiftRows |
| `inv_shift_rows(state)` | 位切片域逆 ShiftRows |
| `mix_columns(state)` | 位切片域 MixColumns |
| `inv_mix_columns(state)` | 位切片域逆 MixColumns |
| `add_round_key(state, key)` | 位切片域 AddRoundKey |
| `encrypt_blocks(blocks, round_keys)` | 位切片路径加密 8 个块 |
| `decrypt_blocks(blocks, round_keys)` | 位切片路径解密 8 个块 |

## 命名空间: `streamcipher::aes`

AES-128 密码实现。

| 函数 | 说明 |
|------|------|
| `expand_key(key)` | 从 16 字节密钥派生 11 个轮密钥 |
| `encrypt_block(block, rk)` | 加密单个 128 位块（标量路径） |
| `decrypt_block(block, rk)` | 解密单个 128 位块（标量路径） |
| `encrypt_ecb(block, key)` | ECB 加密便捷封装 |
| `decrypt_ecb(block, key)` | ECB 解密便捷封装 |
| `encrypt_bitsliced(blocks, count, key)` | 位切片批量加密（含不足 8 个块的标量回退） |
| `encrypt_fast(blocks, count, key)` | 快速路径：AES-NI（若可用）→ bit-sliced → 标量 |
| `has_aesni()` | 运行时 AES-NI 检测 |

## 命名空间: `streamcipher::cipher`

密码模式抽象层。

### `class CipherCtx`
持有密钥材料和模式状态的抽象密码上下文。

| 方法 | 说明 |
|------|------|
| `update(input, output)` | 处理一个数据块 |
| `finalize()` | 完成操作（冲刷缓冲，GCM 模式下生成标签） |
| `tag()` | 获取认证标签（仅 GCM） |
| `algorithm()` / `mode()` | 查询当前上下文配置 |

### 工厂函数
```cpp
auto ctx = streamcipher::cipher::create(algo, mode, key, nonce);
```

支持的模式：
- `Mode::CTR` — Counter 模式（流密码）
- `Mode::GCM` — Galois/Counter Mode（认证加密）
- `Mode::ECB` — Electronic Codebook（主要用于测试）

## 命名空间: `streamcipher::stream`

流式加解密框架。

### `class StreamProcessor`
高层流式加解密处理器，支持零拷贝原地操作。

| 方法 | 说明 |
|------|------|
| `process(span<uint8_t>)` | 原地处理一个数据块 |
| `finish()` | 标记流结束 |
| `tag()` | 认证标签（仅 GCM） |
| `bytes_processed()` | 已处理的总字节数 |
| `create(algo, mode, key, nonce, encrypt)` | 工厂函数 |

**设计要点**：
- CTR 模式加密与解密为同一操作（密钥流异或），`encrypt` 参数不影响行为
- 支持任意次数、任意大小的 `process()` 调用，分块无关（从绝对字节位置计算计数器）
- 零拷贝：直接在传入的 `std::span<uint8_t>` 上原地修改

### 便捷函数
```cpp
size_t encrypt_one_shot(algo, mode, plaintext, ciphertext, key, nonce);
size_t decrypt_one_shot(algo, mode, ciphertext, plaintext, key, nonce);
```
一次性加解密整个缓冲区（适用于小数据 / 测试）。GCM 模式返回时会在密文末尾追加 16 字节认证标签。

## 命名空间: `streamcipher::pipeline`

文件级加密管道。

### `class FilePipeline`
流式文件加解密器，支持进度回调。

| 方法 | 说明 |
|------|------|
| `encrypt_file(input, output, config)` | 加密文件 |
| `decrypt_file(input, output, config)` | 解密文件 |
| `on_progress(fn)` | 设置进度回调 |

### `struct PipelineConfig`
| 字段 | 默认值 | 说明 |
|------|--------|------|
| `chunk_size` | 1 MiB | I/O 分块大小 |
| `parallel` | false | 多线程 CTR |
| `threads` | 0（自动） | 线程数 |
| `on_progress` | 无 | `void(uint64_t done, uint64_t total)` |

**内部缓冲**：实际使用 256 KiB 内部缓冲区进行高效 I/O。

## 命名空间: `streamcipher::simd`

SIMD 抽象层（架构无关）。

### 类型
| 类型 | 说明 |
|------|------|
| `Vec128` | 128 位向量 (`alignas(16)`) |
| `Vec256` | 256 位向量 (`alignas(32)`)，仅在 `STREAMCIPHER_SIMD` 下可用 |

| 函数 | 说明 |
|------|------|
| `xor128(a, b)` | 128 位按位异或（SSE4.1 下用 `_mm_xor_si128`） |
| `gf_mul128(a, b)` | 通道级 GF(2⁸) 乘法 |
| `load128(ptr)` / `store128(ptr, v)` | 非对齐加载/存储 |
| `has_sse41()` / `has_avx2()` / `has_aesni()` | CPU 特性检测 |

### 子命名空间 `streamcipher::simd::aesni`
| 函数 | 对应指令 | 说明 |
|------|----------|------|
| `enc_round(state, rk)` | `_mm_aesenc_si128` | 一轮 AES 加密 |
| `enc_round_last(state, rk)` | `_mm_aesenclast_si128` | 末轮加密（无 MixColumns） |
| `dec_round(state, rk)` | `_mm_aesdec_si128` | 一轮 AES 解密 |
| `dec_round_last(state, rk)` | `_mm_aesdeclast_si128` | 末轮解密 |
| `expand_key_128(key, rk_buf)` | `_mm_aeskeygenassist_si128` | 密钥扩展 |
| `encrypt_blocks(blocks, n, rk)` | — | 批量加密 |
| `decrypt_blocks(blocks, n, rk)` | — | 批量解密 |

## 命名空间: `streamcipher::memory`

内存管理工具。

### `template SlabPool<BlockSize, BlockCount>`
固定大小 Slab 分配器（header-only）。

| 方法 | 说明 |
|------|------|
| `alloc()` | 从池中分配一个块，池耗尽返回 `nullptr` |
| `dealloc(ptr)` | 归还块到池 |
| `capacity()` | 池中总块数 |
| `used()` | 当前已使用块数 |

**实现细节**：预分配 `BlockSize × BlockCount` 字节的连续内存（`alignas(64)`），空闲块通过嵌入式链表管理。alloc/dealloc 均为 O(1)。

### 类型别名
| 别名 | 块大小 | 块数 | 总大小 |
|------|--------|------|--------|
| `AESBlockPool` | 16 B | 16384 | 256 KiB |
| `CtxBufferPool` | 64 B | 4096 | 256 KiB |
| `SIMDBufferPool` | 32 B | 8192 | 256 KiB |

### Span 工具函数
| 函数 | 说明 |
|------|------|
| `is_aligned(span, alignment)` | 检查 span 起始地址是否对齐 |
| `align_offset(span, alignment)` | 返回跳过的字节数以对齐 |
| `split_at(span, offset)` | 将 span 在 offset 处一分为二 |
| `take(span, n)` | 取出最多 n 个元素，返回 (已取, 剩余) |
| `Chunker` | 固定大小分块迭代器 |
