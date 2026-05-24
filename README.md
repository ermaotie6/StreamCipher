# StreamCipher — 高性能流式对称加解密引擎

> 基于现代 C++20 的轻量级、跨平台、常数时间对称加密引擎
>
> 面向云计算与物联网场景下海量数据实时安全传输

---

## 一、项目概述

StreamCipher 是一套从底层代数理论出发、深度整合现代 C++ 特性的高性能对称加解密组件库。项目通过位切片（Bit-slicing）技术替代传统查表法，结合 C++20 `std::span` 零拷贝机制与 x86_64 SIMD/AES-NI 硬件加速，从底层解决了通用密码库在流式大文件处理场景中的内存消耗大、缓存命中率低、侧信道攻击面广等瓶颈问题。

**项目定位**：学术创新项目 / 开源高性能密码库 / 命令行工具原型

**技术栈**：C++20 / CMake 3.20+ / Catch2 / Google Benchmark / AES-NI / SSE4.1 / AVX2

---

## 二、核心创新点

### 2.1 代数化 S-box — 零查表、常数时间

传统 AES 实现依赖 256 字节预计算 S-box 查表，存在两个固有问题：
- **缓存侧信道**：查表操作的缓存命中/缺失模式泄露密钥信息（Cache-timing attack）
- **缓存污染**：256 字节的查表在流式处理中挤占 L1 数据缓存

StreamCipher 通过代数推导完全消除了 S-box 查表：

```
S(x) = Affine(GF_inv(x))
```

其中 `GF_inv(x) = x^254` 通过二进制快速幂实现（14 次纯位运算 GF(2⁸) 乘法），`Affine` 仿射变换通过 `std::rotr` 位旋转实现。所有操作仅使用 AND/OR/XOR/NOT 位运算，固定执行 8 次循环迭代，无数据依赖分支。

### 2.2 Bit-slicing 并行 — SIMD-within-a-register

将 8 个 128-bit AES 块重新排列为 128 个 bit-slice word，每个 word 包含 8 个块同一 bit 位置的值。SubBytes / ShiftRows / MixColumns / AddRoundKey 全部在 bit-sliced 域中以布尔电路形式执行，一次操作处理 8 个块。

### 2.3 零拷贝流式管道

所有公开 API 使用 C++20 `std::span<T>` 传参，全程零数据拷贝。流式处理器（StreamProcessor）和文件管道（FilePipeline）直接在用户提供的缓冲区上原地操作，内存开销恒定 O(1)，不随文件大小增长。

### 2.4 三路执行路径

```
encrypt_fast()
    ├── AES-NI 硬件路径  (x86_64 w/ __AES__)
    ├── Bit-sliced 软件路径 (8 块并行, 常数时间)
    └── 标量后备路径  (单块, 常数时间)
```

---

## 三、项目结构

```
streamcipher/
├── include/streamcipher/          # 公共头文件
│   ├── core/                      # 密码核心
│   │   ├── gf.hpp                 # GF(2⁸) 纯位运算 (mul/inv/xtime/sbox)
│   │   ├── bitslice.hpp           # Bit-slicing 数据结构与操作
│   │   ├── aes.hpp                # AES-128 API
│   │   └── cipher.hpp             # 密码模式抽象 (CTR/GCM/ECB)
│   ├── stream/                    # 流式处理
│   │   ├── stream.hpp             # StreamProcessor 接口
│   │   └── pipeline.hpp           # FilePipeline 文件管道
│   ├── simd/                      # 硬件加速
│   │   ├── simd.hpp               # Vec128/Vec256 + SSE/AVX
│   │   └── aesni.hpp              # AES-NI 指令封装
│   └── memory/                    # 内存管理
│       ├── pool.hpp               # SlabPool 固定大小分配器
│       └── span_utils.hpp         # std::span 工具函数
├── src/                           # 实现文件（镜像 include 结构）
├── tests/                         # 单元测试 (Catch2, 4 套件, 67K+ 断言)
├── benchmarks/                    # 性能基准 (Google Benchmark)
├── examples/                      # 使用范例 (encrypt_file / decrypt_file)
├── apps/                          # CLI 工具 (scipher)
├── docs/                          # 文档
│   ├── architecture.md            # 架构概述
│   ├── api.md                     # API 参考
│   └── implementation.md          # 详细实现文档
├── cmake/                         # CMake 模块
├── scripts/                       # 构建与基准脚本
├── CMakeLists.txt                 # 顶层 CMake (C++20, x86_64 检测)
├── README.md                      # 本文档
└── LICENSE                        # MIT
```

---

## 四、技术架构

### 4.1 分层架构

```
┌──────────────────────────────────────────┐
│  apps/       scipher CLI                  │  用户层
├──────────────────────────────────────────┤
│  stream/     StreamProcessor              │  模式层
│              FilePipeline                 │
├──────────────────────────────────────────┤
│  core/       AES-128 加密/解密            │  密码核心
│              Bit-slicing 轮操作            │
│              GF(2⁸) 代数运算              │
│              CTR / GCM (含 GHASH)         │
├──────────────────────────────────────────┤
│  simd/       SSE4.1 / AVX2 / AES-NI      │  硬件加速
├──────────────────────────────────────────┤
│  memory/     SlabPool / span_utils        │  内存管理
└──────────────────────────────────────────┘
```

### 4.2 CTR 模式加解密数据流

```
文件 → FilePipeline → StreamProcessor
                         │
              nonce+counter → AES encrypt → keystream
                         │
              keystream ⊕ plaintext → ciphertext
                         │
              输出文件 (流式, 无缓冲积压)
```

---

## 五、测试验证

### 5.1 测试结果

```
$ ctest --test-dir build
100% tests passed, 0 tests failed out of 4
```

| 测试套件 | 用例数 | 断言数 | 覆盖内容 |
|----------|--------|--------|----------|
| `gf` | 12 | 67,581 | GF(2⁸) 全运算 + S-box 全表验证 |
| `aes` | 7 | 17+ | NIST 测试向量 + bit-sliced 批量往返 |
| `stream` | 5 | 18 | CTR/GCM 流式 + 跨边界分块 |
| `simd` | 4 | 8 | SIMD 向量操作 + CPU 特性 |

### 5.2 NIST 标准测试向量

- AES-128 加密：`32 43 f6 a8...` → `39 25 84 1d...` ✓
- AES-128 解密：`39 25 84 1d...` → `32 43 f6 a8...` ✓
- S-box：`sbox(0x00)=0x63`, `sbox(0x53)=0xED` ✓
- 往返：`inv_sbox(sbox(x)) == x` (全 256 个值) ✓

---

## 六、快速开始

### 6.1 环境要求

| 依赖 | 版本 |
|------|------|
| 编译器 | GCC 11+ / Clang 14+ (需 C++20) |
| CMake | 3.20+ |
| 测试框架 | Catch2 v3.7.1 (自动获取) |
| 基准测试 | Google Benchmark v1.9.1 (自动获取) |

### 6.2 构建

```bash
cd streamcipher

# 基础构建（仅库）
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)

# 完整构建（含测试、基准、示例、CLI）
cmake -B build -DCMAKE_BUILD_TYPE=Release \
    -DSTREAMCIPHER_BUILD_TESTS=ON \
    -DSTREAMCIPHER_BUILD_BENCHMARKS=ON \
    -DSTREAMCIPHER_BUILD_EXAMPLES=ON \
    -DSTREAMCIPHER_BUILD_APPS=ON
cmake --build build -j$(nproc)
```

### 6.3 运行测试

```bash
ctest --test-dir build
```

### 6.4 CLI 工具

```bash
# 加密文件
./build/apps/scipher encrypt data.txt data.enc

# 解密文件
./build/apps/scipher decrypt data.enc recovered.txt

# 性能基准
./build/apps/scipher benchmark

# 指定模式和密钥
./build/apps/scipher encrypt input.dat output.enc \
    --mode gcm \
    --key 2b7e151628aed2a6abf7158809cf4f3c \
    --nonce f0f1f2f3f4f5f6f7f8f9fafb
```

### 6.5 API 使用

```cpp
#include "streamcipher/streamcipher.hpp"

// CTR 流式加密
auto enc = streamcipher::stream::StreamProcessor::create(
    streamcipher::cipher::Algorithm::AES_128,
    streamcipher::cipher::Mode::CTR,
    key, nonce, true);

enc->process(data_chunk);   // 就地加密
enc->finish();

// GCM 认证加密
auto gcm = streamcipher::stream::StreamProcessor::create(
    streamcipher::cipher::Algorithm::AES_128,
    streamcipher::cipher::Mode::GCM,
    key, nonce, true);

gcm->process(data_chunk);
gcm->finish();
auto tag = gcm->tag();      // 16 字节认证标签

// 文件加密 (带进度)
streamcipher::pipeline::FilePipeline pipe(algo, mode, key, nonce);
pipe.on_progress([](uint64_t done, uint64_t total) {
    printf("\r%llu%%", done * 100 / total);
});
pipe.encrypt_file("input.dat", "output.enc");
```

---

## 七、关键技术指标

| 指标 | 描述 |
|------|------|
| **常数时间** | 所有密码运算固定循环迭代，无数据依赖分支 |
| **零查表** | S-box 通过 GF(2⁸) 逆元+仿射变换实时计算 |
| **内存开销** | O(1) 恒定 (CTR 模式)，GCM 模式额外 O(1) GHASH 状态 |
| **并行度** | Bit-sliced 路径单次处理 8 个 AES 块 |
| **缓存占用** | BitSliceState 128 字节 (alignas(64))，单条缓存行 |
| **代码规模** | ~3500 行 C++ (不含测试/基准) |

---

## 八、交付成果

| 成果 | 说明 |
|------|------|
| 高性能 C++ 加密库 | 完整实现，编译通过，4/4 测试套件全部通过 |
| 命令行工具原型 | `scipher encrypt/decrypt/benchmark` |
| 完整单元测试 | 67K+ 断言，覆盖所有核心模块 |
| 性能基准框架 | Google Benchmark + 内置 CLI 基准 |
| 详细实现文档 | `docs/implementation.md` (约 30 KB) |
| 架构与 API 文档 | `docs/architecture.md` + `docs/api.md` |

---

## 九、后续工作

- [ ] AES-256 与 SM4 国密支持
- [ ] ARM NEON SIMD 后端
- [ ] 完全在 bit-sliced 域中的 Canright 组合域 S-box 电路
- [ ] io_uring 内核旁路 I/O
- [ ] 申请软件著作权

---

## 十、参考文献

1. Käsper & Schwabe, "Faster and Timing-Attack Resistant AES-GCM", CHES 2009
2. Canright, "A Very Compact S-box for AES", CHES 2005
3. NIST FIPS 197, "Advanced Encryption Standard (AES)", 2001
4. NIST SP 800-38D, "GCM Mode", 2007
5. Intel, "AES-NI Instructions", 2010

---

## 十一、许可证

MIT License — 详见 `LICENSE` 文件
