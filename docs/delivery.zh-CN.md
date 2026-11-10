# 本地安装与ZIP打包

本项目交付C++库和文件CLI，没有服务进程、网络端口、数据库迁移或线上部署流程。功能与开发说明见 [README](../README.md) 和 [开发使用](user-guide.zh-CN.md)。

## 源码构建入口

Windows普通PowerShell可使用 scripts/build.ps1。需要Visual Studio 2022 x64 C++工具链、Windows SDK、CMake 3.20+、Ninja（可使用VS附带版本）和Python 3.9+。

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build.ps1 -Variant release
```

脚本自动加载工具链。首次运行允许下载Catch2/Google Benchmark；离线运行可指定本地源码：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build.ps1 -Variant release -Offline -Catch2Source C:\dependencies\Catch2 -BenchmarkSource C:\dependencies\benchmark
```

目录需真实存在。`-BuildDirectory`指定独立产物目录，默认build/delivery-release；`-Jobs`控制并行；`-Interop`额外执行真实cryptography互操作，需要该Python包。未安装预编译工具链时不能只凭源码ZIP运行CLI。

| Variant | 流程 |
|---|---|
| release / software / shared | 构建库、CLI、测试、示例、基准；测试；安装；安装后CLI；独立SDK消费；ZIP；解包CLI与四个SDK示例 |
| debug / asan | 构建与测试；可选Interop；随后结束，不生成分发包 |
| minimal | 只构建库，不要求第三方开发依赖，不执行测试/安装/打包 |

脚本的每步日志和退出码写到**所选构建目录的logs/**。失败立即终止，不以stderr是否非空判断成功。

## 安装与产物

release/software/shared将SDK安装到构建目录的sdk/，ZIP置于构建根目录。文件名来自项目版本、系统与架构；0.1.0的Windows x64名为 `streamcipher-0.1.0-Windows-x86_64.zip`。压缩包SHA256记录在logs/delivery-对应变体-package-sha256.log，解包验证使用同目录下独立的package-check目录。

SDK包括公共头、库、导出CMake配置、许可证、CLI、现行文档、历史Markdown与可编译示例；不安装Catch2或Benchmark。MSVC包随附所需运行库；shared还包含streamcipher.dll。未压缩安装可手动执行：

```powershell
cmake --install build/quickstart --prefix build/sdk
```

安装位置随GNUInstallDirs配置而变，默认布局为include/、lib/、bin/、share/doc/streamcipher/。完整脚本针对默认布局进行包验收。每次输出采用独立构建目录，避免把残留的旧安装文件混成新包。

## 使用解包SDK

`bin/scipher.exe --help`检查CLI，具体参数以帮助为准。Windows x64包运行CLI不需要测试框架或编译器；开发SDK则需要兼容C++20工具链。GCM文件为密文加16字节标签，密钥/nonce/模式单独保存。

消费方将解包根目录加入CMAKE_PREFIX_PATH：

```cmake
find_package(streamcipher 0.1 CONFIG REQUIRED)
target_link_libraries(your_app PRIVATE streamcipher::streamcipher)
```

共享库运行时将解包bin目录加入PATH或使用应用自身的DLL部署方式。静态库消费方需匹配工具链/运行库配置；不承诺跨编译器C++ ABI。包内开发使用、API与架构文档从share/doc/streamcipher/README.md进入；可编译示例在该目录的docs/examples/。

目前仅验证Windows x64；其他平台、恶意目录竞争、断电恢复和完整侧信道性质尚未验证。测试结果不能证明性能排名。
