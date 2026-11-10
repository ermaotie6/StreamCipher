# API参考

精确类型、固定span长度、默认参数与 `noexcept` 以 `include/streamcipher/` 下的公共头为准。本页维护使用契约，不复制整份头文件声明；总入口为 `streamcipher.hpp`。完整可编译示例见 [开发使用](user-guide.zh-CN.md)，资源和目录信任边界见 [架构](architecture.md)。

## 参数与长度：`core/parameters.hpp`

命名空间 `streamcipher::cipher`：

| 符号 | 契约 |
|---|---|
| `Algorithm::AES_128` | 当前唯一算法；key为16字节 |
| `Mode::CTR`、`Mode::GCM` | 流式支持模式；`Mode::ECB`仅保留枚举，工厂拒绝 |
| `Direction::Encrypt`、`Direction::Decrypt` | 强类型方向；旧bool入口仍可用，true为加密 |
| `KEY_SIZE / NONCE_SIZE / BLOCK_SIZE / TAG_SIZE` | 16 / 12 / 16 / 16字节 |
| `ModeSpec` | `tag_size`、`initial_counter`、`max_payload` |
| `mode_spec(mode)` | CTR为 `{0,0,2^36}`；GCM为 `{16,2,2^36−32}` |
| `validate_parameters(algo,mode)` | 验证支持的算法和模式 |
| `validate_length(mode,processed,additional)` | 在无整数回绕的前提下验证总载荷上限 |
| `encrypted_size(mode,payload)` | CTR返回payload，GCM返回payload+16，验证载荷上限 |
| `decrypted_size(mode,encoded)` | CTR返回encoded，GCM减16，验证截断和上限 |
| `AuthenticationError` | 继承 `std::runtime_error`，高层GCM认证失败可按类型捕获 |

非法算法/模式/方向抛 `std::invalid_argument`；标签截断同样抛该类型。载荷超过计数器上限抛 `std::length_error`。空载荷合法。CTR计数器为 `nonce || uint32_be(counter)`，从0开始；GCM数据从2开始，固定96位nonce、空AAD、128位标签。

同一密钥下每次加密必须使用唯一nonce，库不维护跨对象使用历史。CTR不能检测错误密钥或篡改。文件仅保存原始CTR密文或GCM密文后附16字节标签，不包含密钥、nonce或模式。

## 消息上下文：`core/cipher.hpp`

工厂 `cipher::create(algo,mode,key,nonce,bool encrypt=true)` 返回 `std::unique_ptr<CipherCtx>`；另有接受 `Direction` 的重载。key/nonce分别为固定16/12字节span，工厂持有自己的派生状态。

| 方法 | 行为 |
|---|---|
| `update(input,output)` | 输入为字节span，输出容量至少等长；不要求16字节整块；只写输入长度 |
| `finalize()` | 结束消息并计算GCM标签；幂等 |
| `tag()` | GCM结束后返回16字节借用span；结束前或CTR返回空span |
| `verify_tag(expected)` | 结束后比较完整16字节标签；过早、长度错误或不匹配返回false |
| `algorithm()`、`mode()` | 查询配置 |

`update`允许完全原地或不重叠缓冲，拒绝部分重叠及不足容量；检查在输出修改前完成。结束后即使空更新也抛 `std::logic_error`。上下文不可复制；工厂返回的对象由指针管理。标签span依赖对象寿命，需长期保存时自行复制。

**底层GCM解密不会自动阻止候选明文输出。** 调用者必须在finalize后显式verify_tag，并在成功前隔离全部候选明文；需要自动暂存时使用下面的一次性或文件接口。

## 流与一次性：`stream/stream.hpp`

命名空间 `streamcipher::stream`。`StreamProcessor::create(algo,mode,key,nonce,encrypt)`需要显式bool或Direction，返回unique_ptr，处理器不可复制。

| 方法 | 行为 |
|---|---|
| `process(span<uint8_t>)` | 原地处理任意大小分块，保留跨调用的剩余密钥流 |
| `finish()` | 幂等结束并计算标签；之后process抛logic_error |
| `tag()`、`verify_tag(expected)` | 与CipherCtx相同的借用/认证语义 |
| `bytes_processed()` | 成功处理的累计载荷字节数 |

一次性函数参数顺序：

```text
size_t encrypt_one_shot(algo, mode, plaintext, ciphertext, key, nonce);
size_t decrypt_one_shot(algo, mode, ciphertext, plaintext, key, nonce);
```

这两行是参数顺序示意；可编译声明含完整类型并位于公共头。返回输出字节数，0也可能成功。CTR需要等长容量；GCM加密容量至少payload+16，解密容量至少encoded−16。一次性接口支持完全或部分重叠输入输出。

GCM解密使用O(n)内存暂存，验证尾部标签后才修改目标，失败抛AuthenticationError且目标保持原样；标签不足16或容量不足抛invalid_argument。GCM空明文加密仍输出16字节标签。原地process自身不复制用户块，不代表一次性GCM解密或文件I/O全程零拷贝。

## 文件：`stream/pipeline.hpp`

命名空间 `streamcipher::pipeline`。构造 `FilePipeline(algo,mode,key,nonce)`时验证参数并复制key/nonce；不可复制、可移动。每次操作建立新密码上下文，但复用加密对象仍然会复用其nonce，调用方应为新消息配置唯一nonce。

| 方法 | 返回/语义 |
|---|---|
| `encrypt_file(input,output,config={})` | uint64_t输出字节数；GCM包括标签 |
| `decrypt_file(input,output,config={})` | uint64_t明文字节数；GCM先验证再发布 |
| `on_progress(fn)` | 设置默认进度回调 |

`PipelineConfig`字段：

| 字段 | 默认与限制 |
|---|---|
| `chunk_size` | `DEFAULT_CHUNK_SIZE=1<<20`；0也用默认值；超出streamsize上限拒绝；小文件缩减分配 |
| `parallel` | false；true抛invalid_argument |
| `threads` | 0；非零抛invalid_argument |
| `on_progress` | `std::function<void(uint64_t done,uint64_t total)>`，默认空；优先于对象回调 |

回调参数仅包含载荷，不含标签；空载荷调用一次(0,0)。操作开始时复制配置和回调，回调中更改只影响之后的操作；回调抛异常取消当前操作并保留原目标。同一对象重入或移动后继续使用抛logic_error；回调不得移动/销毁当前正在调用它的对象。

普通稳定输入、可信输出目录是前置条件。输入输出别名、输出符号链接和非普通输出会被拒绝。输出在目标同盘独占目录暂存，处理、认证、末尾检查和输出关闭成功后才重命名替换；异常尽力清理，原目标保留。可能抛出文件系统异常、I/O异常、runtime_error、认证及参数异常；资源分配也可能失败。

RAM为O(min(chunk,payload))（空输入仍有最小缓冲），磁盘暂存为O(output)。POSIX目录0700、文件0600；Windows依赖父目录私有ACL。没有恶意目录竞争、快照或断电恢复保证，崩溃可能留下候选明文。进度100%不表示发布成功。上述对象及SlabPool均不允许同对象并发操作。

## AES与位切片

| 头/命名空间 | 入口与约束 |
|---|---|
| `core/aes.hpp` / `aes` | `RoundKeys`为11×16字节；`expand_key(key)`返回调用方管理的轮密钥 |
| 同上 | `encrypt_block/decrypt_block(block,rk)`标量单块；`encrypt_ecb/decrypt_ecb(block,key)`单块包装，无填充 |
| 同上 | `encrypt_bitsliced(blocks,count,key)`处理count个16字节块，完整八块加标量尾块；`encrypt_fast`先尝试AES-NI |
| 同上 | `has_aesni()`同时反映构建启用与CPU能力 |
| `core/bitslice.hpp` / `bitslice` | SliceWord=uint8_t；SLICE_WIDTH=8，BLOCK_BYTES=16，BLOCK_BITS=128，SLICE_BYTES=128；BitSliceState按64字节对齐 |
| 同上 | `pack/unpack`在128字节与位表示间转换；`xor_state/and_state/not_state/or_state`状态运算 |
| 同上 | `sub_bytes/inv_sub_bytes`、`shift_rows/inv_shift_rows`、`mix_columns/inv_mix_columns`、`add_round_key`轮操作 |
| 同上 | `encrypt_blocks/decrypt_blocks(blocks,round_keys)`恰好处理8块，密钥为11个16字节数组 |

低层裸指针接口要求调用者提供足够可读写的块存储；固定span长度也是调用方前置条件，不提供运行时容量恢复。SubBytes当前提取字节使用代数S-box，不是未验证实验电路。调用者返回值/副本中的轮密钥须自行管理与清理。

## GF与SIMD

`core/gf.hpp` / `streamcipher::gf`：GF8=uint8_t，IRREDUCIBLE_POLY=0x1B。constexpr工具为 `mul`、`inv`（0的约定结果为0）、`xtime`、`mul3/9/11/13/14`、`sbox/inv_sbox`。批量 `mul_batch(dst,a,b,n)`、`inv_batch/sbox_batch/inv_sbox_batch(dst,src,n)`使用调用方存储，支持完全原地；不承诺任意部分重叠。

`simd/simd.hpp` / `streamcipher::simd`：

| 类型/函数 | 语义 |
|---|---|
| `Vec128`、`Vec256` | 16/32字节data，alignas(16/32)；公共布局不随构建开关变化 |
| `xor128/xor256` | 按位异或 |
| `gf_mul128/gf_mul256` | 16/32字节通道独立GF(2^8)乘法 |
| `load128/load256`、`store128/store256` | 无对齐要求，调用者提供足够16/32字节存储 |
| `shift_bytes_left(a,shift)` | 16字节循环左旋，shift模16 |
| `has_sse41/has_avx2/has_aesni` | CPU/OS能力，不代表该构建选择了对应实现 |

`simd/aesni.hpp` / `simd::aesni`：`enc_round/enc_round_last/dec_round/dec_round_last`为单轮，`expand_key_128(key,out)`输出176字节；`encrypt_blocks/decrypt_blocks(blocks,count,keys)`使用同一套加密轮密钥，解密内部转换中间轮密钥。不可用时软件回退。单轮dec_round的rk按该轮指令语义提供；完整解密请用decrypt_blocks。

## 内存工具

`memory/secure.hpp`：`secure_zero(span<uint8_t>) noexcept`用volatile存储覆盖指定可写范围；不清除外部副本、寄存器、交换区或磁盘残留。

`memory/pool.hpp`：`SlabPool<BlockSize,BlockCount=1024,BlockAlignment=alignof(std::max_align_t)>`为原始存储池，调用者负责构造/析构对象，池须长于所有分配。不复制、不移动、不线程安全，也不自动擦除。

`alloc()`耗尽返回nullptr；`dealloc(ptr)`忽略空/外来/非槽起点/当前已释放指针；`capacity()`查询容量，`used()`查询已用数。对齐须为可支持指针的2幂，块大小/数量须为正且无容量溢出。步长至少容纳指针并按BlockAlignment向上取整，整个池至少64字节对齐。

别名为AESBlockPool（16×16384）、CtxBufferPool（64×4096）、SIMDBufferPool（32×8192，对齐32）。这些乘积各为256KiB的槽存储，**不是sizeof(pool)**：分配标记、链表头、计数和填充另占空间。

`memory/span_utils.hpp`：`is_aligned(span,alignment)`在alignment=0时false；`align_offset`返回要跳过的字节数，0对齐抛invalid_argument。`split_at(span,offset)`以元素数拆分，超界抛out_of_range；`take(span,n)`截断到可用元素，返回已取与剩余。`Chunker<T>(span,chunk_size)`要求非零，next返回下一片或空span，remaining/done查询进度。align_offset给出字节偏移，不保证该偏移在原span内。
