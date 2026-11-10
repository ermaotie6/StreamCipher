# 性能评估与平台验证

## 探索性测量（2026-11-09）

Windows x64，MSVC 19.44.35217，Release，Google Benchmark 1.9.1。流式矩阵覆盖CTR/GCM、16至1048576字节消息以及17和65536字节分块。软件配置关闭AES-NI及SIMD；默认配置的AES-NI可用。

运行 `benchmarks/bench_stream.exe --benchmark_filter=StreamMatrix --benchmark_min_time=0.05s --benchmark_repetitions=3`，以及 `bench_aes.exe --benchmark_filter=BM_AES_(BitSliced_128B|Scalar_128B|Fast_64K) --benchmark_min_time=0.05s --benchmark_repetitions=3`。完整输出和JSON保留在原工作区的构建日志中，不随源码分发。两种配置顺序运行，测试数据和 key/nonce 固定，仅供基准。此机器报告 14 个逻辑 CPU、Intel64 Family 6 Model 198 Stepping 2。以下为三次实际耗时中位数，块大小 65536 字节，含初始化和结束：

| 配置 | CTR 16 B | CTR 1 MiB | GCM 16 B | GCM 1 MiB |
|---|---:|---:|---:|---:|
| 默认（AES-NI 可用） | 197 ns | 3.34 ms | 2.23 µs | 69.19 ms |
| 软件回退 | 20.09 µs | 1047.09 ms | 54.14 µs | 1113.28 ms |

这是一次本机探索性测量，未控制系统负载或电源状态；尤其 1 MiB 项单次迭代且 Windows CPU 计时粒度较粗，不适合当作严格排名。默认配置下 GCM 1 MiB 明显慢于 CTR，与逐块软件 GHASH 和逐字节模式循环值得后续剖析的现状一致，但该对比并不能单独证明瓶颈。位切片与标量 128 B 的实际耗时中位数分别约 139 µs 和 131 µs；此实现不支持声称位切片一定更快。仅在建立受控基线和独立正确性对照后考虑批处理或 GHASH 优化。

## Linux 后续验收入口

在 Linux x86-64 上准备 CMake 3.20+、C++20 编译器、Python 3.9+ 和本地 Catch2 3.7+ 源码。以下命令尚未在 Linux 实机验证，路径按本机调整：

```sh
cmake -S . -B build/linux-release -DCMAKE_BUILD_TYPE=Release \
  -DSTREAMCIPHER_FETCH_DEPENDENCIES=OFF \
  -DFETCHCONTENT_SOURCE_DIR_CATCH2=/path/to/catch2
cmake --build build/linux-release --parallel
ctest --test-dir build/linux-release --output-on-failure
python3 tests/check_interop.py build/linux-release/apps/scipher
cmake -S . -B build/linux-software -DCMAKE_BUILD_TYPE=Release \
  -DSTREAMCIPHER_FETCH_DEPENDENCIES=OFF -DSTREAMCIPHER_USE_AESNI=OFF \
  -DSTREAMCIPHER_USE_SIMD=OFF -DFETCHCONTENT_SOURCE_DIR_CATCH2=/path/to/catch2
cmake --build build/linux-software --parallel
ctest --test-dir build/linux-software --output-on-failure
python3 tests/check_interop.py build/linux-software/apps/scipher
```

独立互操作需安装 Python `cryptography`。还应在目标平台验证 0700 暂存、失败清理、安装消费和共享库；非 x86 的软件回退需在对应硬件或可信模拟环境单独验证。记录实际命令、编译器、CPU、版本与输出。不要将目标架构检测或 Bash 语法检查当作 Linux 运行证明。

## 基准解释

矩阵的计时包含上下文创建、密钥扩展、流处理和结束；分块大小超过消息时只调用一次 process。每项以载荷字节数报告吞吐，GCM 包含认证计算，但不计磁盘 I/O。对比构建须使用同一机器、编译器和优化选项，单独运行并多次重复；禁用 AES-NI/SIMD 的配置测软件回退。原 AES 基准分别包含标量、八块位切片与 fast 路径，不代表文件或 GCM 性能。要取得跨库、文件 I/O 或 cycles/byte 结果，需另行设计相同功能和计时边界的实验并记录环境；当前矩阵不提供这些指标。
