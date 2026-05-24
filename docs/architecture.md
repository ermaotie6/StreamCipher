# StreamCipher 架构设计

## 概述

StreamCipher 是一个基于现代 C++20 的高性能流式对称加密引擎，专为克服传统密码库（如 OpenSSL）在高吞吐数据流场景下的性能瓶颈而设计，适用于云端服务器和物联网边缘设备。

## 设计原则

1. **全程零拷贝** — 所有缓冲区传递使用 `std::span`，载荷数据无内部拷贝。
2. **构造即常数时间** — 位切片 GF 运算消除查表，根除时序侧信道。
3. **硬件加速** — x86_64 下集成 AES-NI 与 SIMD，附干净的标量回退路径。
4. **缓存友好** — 自定义 SlabPool 分配器与位切片数据布局最小化缓存缺失。
5. **模块化** — 密码逻辑、流式框架、SIMD 层、内存管理清晰分离。

## 分层架构

```
┌─────────────────────────────────────────────┐
│  apps / examples (scipher CLI, 文件工具)     │  ← 用户层
├─────────────────────────────────────────────┤
│  pipeline (FilePipeline, 分块 I/O 编排)      │  ← 编排层
├─────────────────────────────────────────────┤
│  stream (StreamProcessor, CTR/GCM 模式)      │  ← 模式层
├─────────────────────────────────────────────┤
│  cipher (CipherCtx, AES-128 实现)            │  ← 密码核心
│  ├── GF(2⁸) 位运算 (gf.hpp)                   │
│  ├── Bit-slicing (bitslice.hpp)              │
│  └── AES (aes.hpp)                           │
├─────────────────────────────────────────────┤
│  simd (Vec128/Vec256, AES-NI 指令)           │  ← 硬件加速
├─────────────────────────────────────────────┤
│  memory (SlabPool, span_utils)               │  ← 内存管理
└─────────────────────────────────────────────┘
```

## CTR 模式加密数据流

```
文件 → 分块 (1 MiB) → StreamProcessor → CipherCtx (CTR)
                             │
                    counter + key → AES 加密 → 密钥流
                             │
                    密钥流 ⊕ 明文 → 密文
                             │
                    输出文件 (流式, 无缓冲积压)
```

## Bit-Slicing 位切片

传统 AES 实现依赖 256 字节的 S-box 查表，存在两个固有问题：缓存时序攻击面与缓存污染。Bit-slicing 通过以下方式消除查表：

1. 将 `SLICE_WIDTH`（8）个 AES 块打包为转置的位表示 —— 128 个 bit-slice word，每个 word 存有 8 个块同一 bit 位置的值
2. 将 SubBytes 实现为作用在 bit-slice word 上的布尔逻辑（AND/OR/NOT/XOR），而非字节查表
3. 实现 SIMD-within-a-register（SWAR）并行，同时保证常数时间

当前 SubBytes 通过逐字节提取后调用 `gf::sbox()`（本身为常数时间、无查表的代数实现），再注入回 bit-slice 域。完整的 Canright 组合域 GF((2⁴)²) 布尔电路已在源码中以 `#if 0` 预留，待验证后激活。

## 内存模型

- **SlabPool**：从连续预分配区域中分配固定大小块（如 AES 块 16 字节），消除逐块 malloc/free 开销，提升缓存局部性。模板参数化，header-only。
- **std::span**：所有公开 API 以 `std::span<T>` 接受缓冲区参数 —— 零开销、边界安全、无所有权转移。

## 执行路径调度

```
encrypt_fast()
    ├── AES-NI 硬件路径   (x86_64, __AES__ 宏)
    ├── Bit-sliced 软件路径 (8 块并行, 常数时间)
    └── 标量后备路径       (单块, 常数时间)
```

编译时通过 `STREAMCIPHER_USE_AESNI` 和 `STREAMCIPHER_USE_SIMD` 选项控制，运行时通过 CPUID 检测选择最优路径。

## 后续方向

- AES-256 与 SM4 国密支持
- ARM NEON SIMD 后端
- io_uring 内核旁路 I/O（极高吞吐场景）
- 完全在 bit-sliced 域中的 Canright 组合域 S-box 电路
