# StreamCipher

StreamCipher 是一个使用 C++20 实现的 AES-128 流式加解密原型，提供可嵌入的库和文件命令行工具 `scipher`。项目支持 CTR 和 GCM 模式，适合研究流式处理、软件密码实现与硬件加速的工程权衡。

项目尚未经过产品认证或完整侧信道审计。使用前请结合应用的安全要求评估其适用性。

## 功能

- **流式处理**：支持任意长度和分块边界，提供原地流接口和一次性内存接口。
- **文件处理**：顺序分块读写，内存占用受分块大小限制；GCM 解密在认证成功后才发布输出。
- **密码实现**：提供标量 AES、八块位切片实验路径，以及运行时 AES-NI 分派和软件回退。
- **集成方式**：提供 CMake 库目标、可安装的包配置、公共头文件和示例。

当前支持 16 字节密钥、12 字节 nonce、空 AAD 和 16 字节 GCM 标签。CTR 计数器从 0 开始，GCM 数据计数器从 2 开始。GCM 文件格式为密文后附标签；CTR 文件仅包含密文。文件不保存模式、密钥或 nonce。

## 构建

需要 C++20 编译器和 CMake 3.20 或更高版本。以下命令适用于已加载 Visual Studio 2022 x64 开发环境且安装 Ninja 的 PowerShell。Windows x64/MSVC 已验证；Linux、macOS 和 ARM 尚未实机验证。

仅构建库和命令行工具，不下载测试依赖：

```powershell
cmake -S . -B build/quickstart -G Ninja -DCMAKE_BUILD_TYPE=Release -DSTREAMCIPHER_BUILD_TESTS=OFF -DSTREAMCIPHER_BUILD_EXAMPLES=OFF -DSTREAMCIPHER_BUILD_BENCHMARKS=OFF -DSTREAMCIPHER_FETCH_DEPENDENCIES=OFF
cmake --build build/quickstart --parallel 8
.\build\quickstart\apps\scipher.exe --help
```

普通 PowerShell 中的工具链配置、离线依赖和其他构建选项见[开发与使用](docs/user-guide.zh-CN.md)。

## 命令行使用

以下示例使用固定测试参数，仅用于演示。实际使用时须安全管理密钥，并为同一密钥下的每次加密使用唯一 nonce。

```powershell
$key = '2b7e151628aed2a6abf7158809cf4f3c'
$nonce = 'f0f1f2f3f4f5f6f7f8f9fafb'
Set-Content -LiteralPath build/quickstart/input.txt -Value 'StreamCipher demo' -Encoding utf8

.\build\quickstart\apps\scipher.exe encrypt build/quickstart/input.txt build/quickstart/encrypted.bin --mode gcm --key $key --nonce $nonce --no-progress
.\build\quickstart\apps\scipher.exe decrypt build/quickstart/encrypted.bin build/quickstart/recovered.txt --mode gcm --key $key --nonce $nonce --no-progress
(Get-FileHash -LiteralPath build/quickstart/input.txt).Hash -eq (Get-FileHash -LiteralPath build/quickstart/recovered.txt).Hash
```

`--key` 和 `--nonce` 分别接受 32 个和 24 个十六进制字符。`--mode` 可选 `ctr` 或 `gcm`，默认 `ctr`；`--chunk-size` 可设置分块大小。成功退出码为 0，错误为非零。完整参数见 `scipher --help` 和[命令行说明](docs/user-guide.zh-CN.md#命令行)。

## 作为库使用

将源码作为子目录引入：

```cmake
add_subdirectory(path/to/StreamCipher)
target_link_libraries(your_app PRIVATE streamcipher::streamcipher)
```

或安装后通过 CMake 包使用：

```cmake
find_package(streamcipher 0.1 CONFIG REQUIRED)
target_link_libraries(your_app PRIVATE streamcipher::streamcipher)
```

公共总入口为 `<streamcipher/streamcipher.hpp>`。内存、流和文件接口的完整示例见 [SDK 示例](docs/examples/)；参数、异常和生命周期约束见 [API 参考](docs/api.md)。库目标向消费者传播 C++20 要求，不承诺跨编译器的 C++ ABI 稳定性。

## 安全与使用边界

- CTR 不提供认证，无法检测篡改或错误密钥；需要完整性保护时应使用 GCM。
- 调用方负责密钥保管和 nonce 唯一性。库不生成或保存密钥及 nonce；命令行参数也可能被系统进程信息或命令历史记录。
- 低层流式 GCM 解密会输出候选明文，调用方必须在认证成功前隔离这些数据。一次性和文件解密接口会先验证，再发布明文；文件认证失败时保留已有目标。
- 文件接口要求稳定的普通输入文件和可信输出目录，需与输出大小相当的暂存磁盘空间。它不保证恶意目录竞争防护或崩溃恢复。
- 当前不支持 AES-256、SM4、AAD、口令 KDF 或并行文件处理；旧版错误 GCM 格式不兼容当前实现，背景见[历史索引](docs/history/README.md)。

## 测试

在已配置 MSVC 和 Ninja 的环境中，可构建并运行默认测试：

```powershell
cmake -S . -B build/dev -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build/dev --parallel 8
ctest --test-dir build/dev --output-on-failure
```

测试需要 Catch2 3.7+；依赖缺失时，默认配置允许下载。Python 3.9+ 用于架构和 CLI 等检查，独立互操作检查另需 `cryptography`。离线构建、软件回退、共享库、ASan 和打包验证见[开发与使用](docs/user-guide.zh-CN.md)及[本地打包](docs/delivery.zh-CN.md)。

## 整体架构

项目由单一 CMake 库和命令行工具组成，主要目录与文件如下：

```text
StreamCipher/
	apps/                                   # 命令行程序
		main.cpp                        # 进程入口与异常处理
		options.cpp                     # 命令行参数解析
		commands.cpp                    # 文件操作与基准命令
	include/streamcipher/                   # 库的公共头文件
		streamcipher.hpp                # 公共接口总入口
		core/                           # AES、有限域与密码上下文接口
		stream/                         # 流处理与文件接口
		simd/                           # CPU 能力与 AES-NI 接口
		memory/                         # 内存池、视图与清理工具
	src/                                    # 库的内部实现
		core/                           # 密码算法与消息状态
			cipher.cpp              # CTR/GCM 状态机
			parameters.cpp          # 模式参数与长度校验
			aes.cpp                 # 标量 AES 与位切片封装
			aes_dispatch.cpp        # 独立 AES fast 接口分派
			bitslice.cpp            # 八块位切片 AES
			gf.cpp                  # 有限域批量运算
			ghash.cpp               # GCM 认证计算
		stream/                         # 流与文件适配
			stream.cpp              # 原地处理和一次性接口
			pipeline.cpp            # 文件分块 I/O 与处理编排
		io/                             # 输出事务
			output_transaction.hpp  # 暂存文件与成功后发布
		detail/                         # 内部认证比较与清理工具
		simd/                           # CPU 能力检测与 AES-NI 实现
		memory/                         # 内存清理实现
	tests/                                  # 单元、回归、CLI 和互操作测试
		consumer/                       # 独立 CMake 消费项目
	benchmarks/                             # AES、有限域和流处理基准
	examples/                               # 文件加解密示例
	docs/                                   # 技术文档
		examples/                       # 可编译的 SDK 示例
		decisions/                      # 架构决策记录
		history/                        # 历史资料
	cmake/                                  # 平台检测与 CMake 包配置
	scripts/                                # 构建、打包和检查脚本
	CMakeLists.txt                          # 项目构建入口
	CMakePresets.json                       # CMake 构建预设
	README.md                               # 项目介绍与快速开始
	LICENSE                                 # MIT 许可证
```

文件处理依次经过 `FilePipeline`、`StreamProcessor` 和 `CipherCtx`；输出事务在 GCM 认证成功后发布解密结果。AES 使用运行时硬件分派并保留软件回退。详细设计见[架构与设计](docs/architecture.md)。

## 文档

- [开发与使用](docs/user-guide.zh-CN.md)：环境、构建、CLI 和 SDK 集成。
- [API 参考](docs/api.md)：公开接口、参数和错误处理。
- [架构与设计](docs/architecture.md)：模块边界、数据流和安全前置条件。
- [性能评估与平台验证](docs/architecture-assessment.zh-CN.md)：测量方法和平台验证范围。
- [本地打包](docs/delivery.zh-CN.md)：安装、ZIP 和独立消费验证。

## 许可证

[MIT License](LICENSE)
