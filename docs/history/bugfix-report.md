> 历史归档：保留当时的结论与命令，不代表当前状态。当前文档见 [历史索引](README.md)。

# StreamCipher 缺陷排查与修复报告

日期：2026-09-20  
工作目录：`F:\StreamCipher`  
来源：[ermaotie6/StreamCipher](https://github.com/ermaotie6/StreamCipher)  
基线：`main`，`542a4be35a8f80f7c8d8c666798e6d136994ccff`  
本地修复分支：`fix/correctness-and-safety`

## 结论

本次检查覆盖全部运行时代码、公开头文件、CMake、CLI、示例和现有测试。重点修复了 GCM 不认证且不符合标准、CTR 分块错误、AES-NI 构建及解密错误、缓冲区越界风险、文件损坏风险和失效测试。

原版默认启用 AES-NI 时构建失败。关闭 AES-NI 后，原有 4 个测试套件全部通过，但新增的首批 5 个回归用例全部失败：标准 GCM 结果、篡改标签拒绝、GCM 分块一致性、底层 CTR 分块一致性、AES 单轮软件回退。修复后这些用例全部通过。

当前验证范围内未再发现未修复的可复现错误。此结论不等同于证明所有平台、所有输入下绝无缺陷；平台范围及未实现功能见最后一节。

## 修复清单

| 级别 | 原问题及影响 | 修复与验证 |
|---|---|---|
| 严重 | GCM 一次性及文件解密完全不校验标签，篡改密文也会被当作成功解密 | 完整校验 16 字节标签；失败抛异常；一次性解密不修改调用方输出，文件解密不替换目标。逐字节篡改、错误密钥/nonce、截断用例均覆盖 |
| 严重 | GCM 第一数据块使用 J0 的计数器 1，GHASH 位序/约简错误 | 数据计数器从 2 开始；按 SP 800-38D 的位序与多项式重写乘法；标准向量及独立实现比对 |
| 高 | GCM 每次 update 都对部分块补零，认证结果取决于分块方式 | 保存未满 16 字节的认证块，只在消息结束时补零；验证分块大小 1–33 字节及文件边界 |
| 高 | GCM 忽略加解密方向，解密时认证明文而非输入密文 | 工厂增加默认 true 的 encrypt 参数，解密传 false；直接支持原地操作，先保存输入字节再覆盖 |
| 高 | 底层 CTR 丢弃跨 update 的剩余密钥流，结果与流式 API 不一致 | 两层共用同一状态机，按绝对位置使用计数器及缓存密钥流；逐字节处理与一次性处理一致 |
| 高 | 32 位计数器可回绕重用密钥流 | CTR 限制为 2^36 字节，GCM 为 2^36−32 字节；提前校验总长度和溢出，测试精确边界 |
| 高 | update/一次性函数不检查输出容量；GCM 输入短于标签时仍尝试解密 | 增加容量、模式、算法和截断检查；明确原地/重叠规则；ASan 验证 |
| 高 | 文件输出直接截断目标，输入输出相同会破坏源文件；I/O 失败可能被当作成功 | 检查同路径/硬链接等别名；暂存、检查读写及关闭结果后替换；异常保留原目标并清理暂存 |
| 高 | AES-NI 密钥扩展把运行时变量传给要求立即数的 intrinsic，默认构建失败 | 使用编译期模板常量展开轮常量，Debug/Release 验证 |
| 高 | AES-NI 解密直接使用加密轮密钥，解密结果错误 | 对中间轮密钥执行 AESIMC；与标量和随机块结果交叉比对 |
| 高 | AES 单轮软件回退仅执行 XOR，不是 AES | 实现完整正逆轮变换；关闭 AES-NI 的构建验证全部公开轮函数 |
| 高 | 将 AES/AVX2 编译选项施加到整个库，编译宏被误当成 CPU 运行时能力 | 移除全库 ISA 要求，增加 CPUID/OS 状态检测；AES 指令隔离并在运行时分派；encrypt_fast 真正使用硬件路径 |
| 高 | CLI 默认使用公开固定密钥和固定 nonce | 加解密必须显式提供 --key 和 --nonce；示例程序仍明确定位为固定测试参数演示 |
| 中 | finalize 重复调用改变标签，结束后还能继续处理 | finalize/finish 幂等；结束后 update/process 抛逻辑错误；标签在结束前不可获取 |
| 中 | CLI 忽略未知/缺值参数，benchmark 忽略 size/iterations，空文件返回失败 | 严格解析参数和数值溢出；落实基准选项；正常空输出退出码为 0；错误统一非零并输出原因 |
| 中 | PipelineConfig.on_progress 从未调用，并行选项静默无效 | 使用配置回调并定义优先级；空文件回调一次；未实现的并行设置明确拒绝 |
| 中 | SlabPool 的小块/非对齐块放不下链表指针；重复/非法释放可破坏状态 | 按指针容量和 max_align_t 调整步长，检查容量溢出，追踪分配状态并拒绝非法释放 |
| 中 | span 辅助函数零对齐取模、非法拆分或零大小分块 | 明确返回 false 或抛异常，避免除零、越界及无法前进的分块 |
| 中 | GF/位切片含秘密相关分支，与常数时间宣称不符；GF 批量接口 restrict 限制原地使用 | 改为掩码/固定循环；GF 批量运算支持完全原地操作；收窄文档中的常数时间承诺 |
| 中 | 基准缺失命名空间，依赖测试配置导致默认完整构建问题；安装包不完整 | 修复基准编译、关闭第三方依赖自身测试；导出 CMake 包和 C++20 要求；支持 Windows DLL 导出和运行时复制 |
| 中 | S-box 往返测试循环从不执行，GF 测试漏掉 0xFF，位切片解密测试实际上调用标量 | 修正循环范围，测试真正的位切片解密；加入独立标准向量、篡改及失败路径测试 |

还同步修正了 API 和 README 对 GCM、文件内存/磁盘占用、错误语义、分块、SIMD 和安装使用的说明。

## 验证结果

环境：Windows x64，MSVC 19.44.35217，CMake 4.3.0-rc3，Catch2 3.7.1，Google Benchmark 1.9.1。独立交叉验证使用 Python cryptography 48.0.0。

| 检查 | 结果 |
|---|---|
| 默认 Release，含库、CLI、示例和全部基准 | 构建通过；7/7 CTest 套件通过 |
| Debug | 完整构建通过；7/7 套件通过 |
| 关闭 SIMD 和 AES-NI 的 Release | 构建通过；7/7 套件通过 |
| MSVC AddressSanitizer Release | 构建通过；7/7 套件通过，未报告内存错误 |
| Windows 共享库及相关程序 | 库、CLI、示例、基准完整构建通过；7/7 套件通过 |
| 安装后的独立消费项目 | find_package、11 个公开头文件独立编译、链接和 GCM 往返运行通过 |
| 手册附带示例工程 | `docs/examples` 使用安装后的 CMake 包独立配置、编译并运行；4 个示例均通过，FilePipeline 加解密前后 SHA-256 一致 |
| 独立 cryptography 比对 | 200/200 用例通过：CTR 100 组，GCM 100 组；检查密文/标签以及双向解密，覆盖随机参数、空输入及 1 MiB±1 边界 |
| 基准运行冒烟检查 | AES 快速路径、GCM 流式基准及基准列表正常运行；本次不是严谨性能测评 |

6 个 C++ 套件共 **50 个测试用例、73,889 次断言**；另有 Python CLI 集成测试。保留的测试输出位于 `build/*-tests.log`，构建输出位于 `build/*-build.log`；原始失败复现见 `build/baseline-tests.log`。

标准依据：[NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)，[NIST AES-GCM 示例](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf)。新增测试包含其无 AAD、多块 AES-128 示例。

完整中文使用说明见 [`docs/user-guide.zh-CN.md`](../user-guide.zh-CN.md)，并附有可独立构建的 [`docs/examples/`](../examples) 示例工程。文档以当前修复分支的实际接口和限制为准。

### 常用复现命令

```powershell
cmake -S . -B build/verify -G "Visual Studio 17 2022" -A x64
cmake --build build/verify --config Release --parallel 8
ctest --test-dir build/verify -C Release --output-on-failure
python tests/check_interop.py build/verify/apps/Release/scipher.exe
```

独立交叉验证脚本需要 cryptography；普通 C++ 测试不需要。首次配置会从 GitHub 获取 Catch2 和 Google Benchmark，需要网络。拉取时直连 GitHub 超时，本次使用系统已有的 `127.0.0.1:7890` 代理完成同步，没有修改全局 Git 代理设置。

## 兼容性与迁移

1. **旧版 GCM 文件不兼容。** 原实现的计数器和认证均不符合标准。修复版不会静默接受旧格式或绕过认证；有历史数据时先保留原文件及旧程序备份，再通过可信流程迁移。CTR 的原高层流式格式保持不变；旧底层 CTR 若按非 16 字节边界分块生成数据，可能已有错误。
2. **CLI 必须显式指定密钥和 nonce。** 文件格式仍为 CTR 原始密文，或 GCM 密文后接 16 字节标签；密钥、nonce、模式由调用方保存，不写入文件。每次加密都应在同一密钥下使用唯一 nonce。
3. **错误通过异常表示。** 空输出合法，不能再用返回字节数是否大于零判断成功。不支持的算法/模式现在会抛异常。修改过的公开接口及 DLL 需要重新编译客户端。
4. **流式 GCM 需要显式 verify_tag。** finish/finalize 只计算标签；直接使用流式接口时，明文在校验成功前不能使用。一次性解密与 FilePipeline 已自动处理认证和暂存。
5. **文件管道需要暂存磁盘空间。** 内存按 chunk_size 有界；暂存输出与文件大小相关。成功后替换目标，失败时保留原目标。详细权限及崩溃清理约定见 API 文档。

## 验证边界

- 已在本机 Windows x64 验证；没有 Linux/macOS/ARM 真机结果，也没有无 AES 指令的实体 CPU 测试。关闭 AES-NI 的构建已覆盖软件后备路径。GCC/Clang 的目标函数属性路径尚未在本轮实际编译运行。
- 64 GiB 附近的计数器限制通过同一校验函数的边界测试验证，未实际加密如此大的文件。
- 当前支持 AES-128、12 字节 nonce、16 字节 GCM 标签和空 AAD。AES-256、SM4、AAD、并行文件处理及纯布尔电路 S-box 不属于当前已实现功能。
- 修复了可见的秘密相关分支，但没有完成所有编译产物的侧信道审计、FIPS 认证或形式化证明。也未对断电、进程强杀、恶意并发修改输入文件作持久性保证。

改动保存在本地修复分支的工作区，未提交或推送到 GitHub。
