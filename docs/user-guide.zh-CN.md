# 开发与使用

本页介绍环境、构建、CLI、SDK集成和排错。功能入口见 [README](../README.md)，协议和资源前置条件见 [API](api.md) 与 [架构](architecture.md)。

## 环境与依赖

- C++20 编译器、CMake 3.20+；本机验证为 Windows x64、Visual Studio 2022 C++工具链和 Windows SDK。
- Ninja 用于预设和 PowerShell交付脚本。`scripts/build.ps1` 可加载MSVC环境；手动Ninja命令需要先加载Visual Studio的x64开发环境。
- 库与CLI无第三方库运行依赖。测试需要 Catch2 3.7+；Google Benchmark 1.9+ 只在开启基准时需要。优先已有target/已安装包，否则按开关下载固定标签的源码。
- Python 3.9+ 用于架构、CLI、验证器检查；独立互操作另需 `cryptography`。缺少Python时CMake不会注册这三项Python检查，应检查 `ctest -N`，不能误报为全套验证。
- MSVC ASan 要求编译器安装对应组件；预编译测试依赖应与容器注解/运行库配置一致。

项目没有 `.env`、运行服务、容器、数据库、监听端口或服务端部署步骤。CMake参数是构建配置，CLI参数是运行配置。

## 构建

README提供不下载依赖的CLI快速开始。完整Windows交付（含测试、基准、示例、安装和ZIP）可在普通PowerShell中运行：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build.ps1 -Variant release
```

以上无离线开关时允许下载。离线时提供实际存在的目录，例如：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build.ps1 -Variant release -Offline -Catch2Source C:\dependencies\Catch2 -BenchmarkSource C:\dependencies\benchmark
```

两个源码目录是示例路径，分别应含对应依赖的 `CMakeLists.txt`。本地已有缓存也可显式指定；不要依赖他人的机器路径。`-BuildDirectory` 改变产物位置，`-Jobs` 必须为正数。日志写入该构建目录下的 `logs/`。各变体的后续步骤见 [打包说明](delivery.zh-CN.md)。

只构建库，不依赖任何测试工具：

```powershell
cmake -S . -B build/library -G Ninja -DCMAKE_BUILD_TYPE=Release -DSTREAMCIPHER_BUILD_TESTS=OFF -DSTREAMCIPHER_BUILD_APPS=OFF -DSTREAMCIPHER_BUILD_EXAMPLES=OFF -DSTREAMCIPHER_BUILD_BENCHMARKS=OFF -DSTREAMCIPHER_FETCH_DEPENDENCIES=OFF
cmake --build build/library --parallel 8
```

手动开发构建可用已安装Catch2，或用本地源码：

```powershell
cmake -S . -B build/dev -G Ninja -DCMAKE_BUILD_TYPE=Release -DSTREAMCIPHER_FETCH_DEPENDENCIES=OFF -DFETCHCONTENT_SOURCE_DIR_CATCH2=C:/dependencies/Catch2
cmake --build build/dev --parallel 8
ctest --test-dir build/dev --output-on-failure
```

Visual Studio多配置生成器需要在构建与测试时分别增加 `--config Release` 和 `-C Release`；可执行文件多一层 `Release/`。不要在已有构建目录中切换生成器。

### CMake配置

下表以顶层工程为默认；嵌入父工程时测试、示例和CLI默认OFF，依赖下载默认OFF。

| 选项 | 默认 | 含义 |
|---|---|---|
| `STREAMCIPHER_BUILD_TESTS` | ON | 7套C++、诊断、公共头隔离及可用的Python检查 |
| `STREAMCIPHER_BUILD_APPS` | ON | 构建 `scipher` |
| `STREAMCIPHER_BUILD_EXAMPLES` | ON | 构建两个CTR教学程序 |
| `STREAMCIPHER_BUILD_BENCHMARKS` | OFF | Google Benchmark场景 |
| `STREAMCIPHER_FETCH_DEPENDENCIES` | ON | 允许获取缺失开发依赖；OFF且无依赖时明确报错 |
| `STREAMCIPHER_USE_SIMD` | ON | 启用编译期可用的向量helper实现 |
| `STREAMCIPHER_USE_AESNI` | ON | x86_64可编译AES-NI路径，执行仍须CPU支持 |
| `STREAMCIPHER_ENABLE_ASAN` | OFF | 项目目标与源码开发依赖的地址消毒器 |
| `BUILD_SHARED_LIBS` | OFF（CMake未另行指定时） | 构建共享库；公共头布局不随开关变化 |

`CMakePresets.json` 提供 release/debug/software/shared/asan/minimal；前五组有测试预设。它不加载MSVC工具链。软件配置关闭SIMD和AESNI，minimal关闭测试/CLI/示例和下载。

```powershell
cmake --preset software
cmake --build --preset software
ctest --preset software
```

Linux/macOS可使用CMake或 `scripts/build.sh`，但尚未实机验证。该Bash脚本默认同时开启测试、基准、示例和CLI；`scripts/benchmark.sh` 查找所选目录/配置的三个基准程序。不要将语法检查等同于平台验收。

## 命令行

实际帮助由 `scipher --help` 输出。路径中有空格时加引号。选项名和值分开写，不支持 `--key=...`。

```text
scipher encrypt <input> <output> --key <hex> --nonce <hex> [options]
scipher decrypt <input> <output> --key <hex> --nonce <hex> [options]
scipher benchmark [--size 1M] [--iterations 10]
scipher --help
```

| 文件选项 | 约束 |
|---|---|
| `--mode ctr` / `--mode gcm` | 默认CTR；需要认证时显式GCM |
| `--key` | 必填，32个十六进制字符（16字节） |
| `--nonce` | 必填，24个十六进制字符（12字节） |
| `--chunk-size` | 正整数，可带K/M/G（1024幂次），默认1MiB |
| `--no-progress` | 关闭stderr进度 |

每个选项只允许一次，未知/重复/缺值/不属于当前命令的选项均失败。`benchmark` 仅接受 `--size` 和 `--iterations`，均为正数，size支持K/M/G；使用固定测试数据，不读取用户文件。

成功退出码0，包括空文件；异常退出码非零并向stderr输出原因。stdout为完成信息或测速结果，stderr为进度与错误。进度100%不表示认证或发布已经完成。

密文没有文件头：CTR仅为等长密文，GCM为密文后附16字节标签；文件内没有模式、密钥或nonce。认证失败、读取/写入/回调异常不会替换已有目标。输入输出别名、非普通文件输出和输出符号链接会被拒绝；输出父目录须已存在。每次加密应使用同密钥下未用过的nonce。

## SDK集成与示例

源码嵌入：

```cmake
add_subdirectory(path/to/StreamCipher)
target_link_libraries(your_app PRIVATE streamcipher::streamcipher)
```

库target传播C++20要求，不改变父目录的C++标准；开发目标默认关闭。安装后消费：

```powershell
cmake --install build/quickstart --prefix build/sdk
cmake -S docs/examples -B build/manual -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="$PWD/build/sdk"
cmake --build build/manual --parallel 8
.\build\manual\memory_gcm.exe
```

消费方的 `CMakeLists.txt` 使用：

```cmake
find_package(streamcipher 0.1 CONFIG REQUIRED)
target_link_libraries(your_app PRIVATE streamcipher::streamcipher)
```

公共总入口是 `<streamcipher/streamcipher.hpp>`，也可按需包含模块头。SDK不承诺跨编译器C++ ABI；Windows共享库消费者运行时须能找到安装目录 `bin/streamcipher.dll`，例如将该目录临时加入PATH。

可编译示例是权威的完整用法，不在多份文档粘贴同一程序：

| 示例 | 说明 |
|---|---|
| [memory_gcm.cpp](examples/memory_gcm.cpp) | 内存往返；篡改标签后输出保持不变 |
| [stream_modes.cpp](examples/stream_modes.cpp) | 不同分块的流处理，GCM显式验签 |
| [file_gcm.cpp](examples/file_gcm.cpp) | 三个路径参数：输入、密文、恢复文件 |
| [core_and_memory.cpp](examples/core_and_memory.cpp) | AES、模式、内存池的对象生命周期 |

全部使用固定演示密钥/nonce，不构成密钥生成方案。顶层 `examples/` 的两个程序是固定参数CTR教学示例，保留独立用途。

## 测试与静态检查

```powershell
ctest --test-dir build/dev --output-on-failure
python scripts/check_architecture.py
python tests/check_interop.py build/dev/apps/scipher.exe
```

最后一条需要Python `cryptography`，执行CTR100和GCM100组独立密文/标签及双向解密对照。CLI和互操作检查在 `-O` 或 `PYTHONOPTIMIZE` 下仍执行实际校验；`tests/test_verification.py` 注入坏退出码/坏数据验证检测能力，其模拟不替代真实互操作。

测试入口以 `tests/CMakeLists.txt` 为准：GF、AES、stream、SIMD、regressions、pipeline、contracts；三个历史诊断仍检查错误退出码。构建还独立编译每个公共头。Python可用时加architecture和verification，启用CLI时再加cli。可用 `ctest --test-dir build/dev -N` 查看实际注册项。

用 `scripts/build.ps1 -Variant software` 选择软件配置；debug、shared、asan同样各自传一个Variant值；具体是否打包见交付文档。基准定义和探索性测量见 [性能评估与平台验证](architecture-assessment.zh-CN.md)，不能作为跨库性能排名。

## 常见问题

| 现象 | 处理 |
|---|---|
| 找不到cl、标准头或Windows SDK | 手动Ninja需开发者终端；普通终端用PowerShell交付脚本，确认安装C++工具链/SDK |
| 离线缺少Catch2或Benchmark | 提供已安装包或实际本地源码路径；仅库/CLI可关闭开发目标 |
| GCM authentication failed | 核对模式/密钥/nonce/完整文件，检查是否篡改或修复前错误GCM；不绕过验签 |
| CTR解密退出0但内容错误 | CTR没有认证，错误参数无法自动发现；需要检测篡改时选GCM |
| 空输出返回0字节 | 正常；用异常/进程退出码判断成功 |
| 进度100%后失败 | 认证、末尾检查、关闭和发布仍可能失败；进度不代表提交成功 |
| 输出目录不存在或目标不合规 | 先创建可信目录；不要输出到源文件别名或符号链接 |
| 想输入口令、开AAD或并行 | 当前没有口令KDF/AAD/并行接口；不能把口令当作十六进制密钥 |
| 判断AES-NI是否启用 | `aes::has_aesni()`反映构建开关与CPU；`simd::has_aesni()`仅报告硬件能力 |

目录竞争防护、崩溃残留、候选明文和并发约束详见 [架构](architecture.md)。发现故障时保留输入和错误日志，不修改正确的测试预期。
