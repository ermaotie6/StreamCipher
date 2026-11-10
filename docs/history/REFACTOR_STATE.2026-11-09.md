# 本轮状态（2026-11-09）

分支 `codex/audit-20261109`；起点为大量用户未提交改动。基线状态和逐文件 SHA256 在 `build/audit-20261109/logs/baseline-status.txt`、`baseline-manifest.json`；已跟踪文件补丁在同目录。不要 reset、clean 或覆盖用户改动。将本轮触及文件的原字节分别保存在 `build/audit-20261109/*.before.py`；恢复前先核对是否有后续编辑。

基线：`powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build.ps1 -Variant release -BuildDirectory build/audit-20261109/release -Offline -Catch2Source build/baseline/_deps/catch2-src -BenchmarkSource build/fixed/_deps/google_benchmark-src -Interop`：MSVC x64 离线配置、构建、13/13 CTest、独立互操作 CTR 100/GCM 100、安装及消费、ZIP 解包及示例通过。原始日志在 `build/audit-20261109/release/logs/` 和 `build/audit-20261109/logs/driver.log`。构建脚本没有单独类型检查目标；公共头隔离编译和架构检查包含在构建/CTest 中。

A01 已完成：先增加隔离夹具并运行 `python tests/test_verification.py`，两个负例均未被检查器拒绝，退出 1；见 `logs/architecture-before.log`。随后只豁免总入口的层间依赖规则，让平台头和构建宏通用检查仍执行。保留合法总入口通过用例及两条负例，并检查具体错误消息。

修改后实际验证：

- 与基线相同的 `scripts/build.ps1` 命令，`-BuildDirectory` 改为 `build/audit-20261109/after`：离线配置、构建、13/13 CTest、CTR/GCM 各 100 独立互操作、安装后 CLI、消费项目、ZIP 解包和示例均通过；`logs/after-driver.log` 和 `after/logs/`。
- `python -O tests/test_verification.py`：两项测试通过，含检查器故障注入和既有验证脚本的普通/优化/环境变量组合；`logs/verification-optimized.log`。`python scripts/check_architecture.py` 通过；四个 Python 脚本 `python -m py_compile` 通过；`git -c core.safecrlf=false diff --check` 通过。
- 用起点清单逐文件比对 SHA256，原文件中仅 `scripts/check_architecture.py`、`tests/test_verification.py` 改变；`logs/increment-audit.txt`。本轮新增本计划与状态两份文档；基线已有用户变更不计入本轮。

最终复核：由同一执行者在实现和验收后单独对照两份原文件审查增量，而非独立人员签字。总入口仍可包含跨层公共头；两条通用检查不再被跳过；测试用临时夹具，断言特定失败原因，没有改变既有断言或运行时代码。认证后发布与文件失败回滚路径保持，测试通过；没有发现有证据支持的阻塞性问题。检查器是文本模式检查，并非完整 C++ 依赖或条件编译分析；Windows x64 外的平台、侧信道、恶意目录和崩溃恢复未在本轮验证。基线没有原有失败，本轮没有新失败。范围内无未解决高严重度问题；下一项必需任务：无。不得将历史配置结果当作本轮结果。
