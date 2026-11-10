# 本轮审计与收敛计划（2026-11-09）

基线为 `codex/audit-20261109` 分支创建时的未提交工作区，不是 HEAD。前轮已完成的架构决策见 `docs/decisions/0001-architecture-boundaries.md`，不因风格重做。CLI → FilePipeline → StreamProcessor → CipherCtx；OutputTransaction 独立负责认证后的发布。CTR 计数器从 0、GCM 从 2 开始；12 字节 nonce、空 AAD、末尾 16 字节 GCM 标签、公共头和 CLI 行为保持。

## A01：总入口绕过架构检查

- 证据：`scripts/check_architecture.py` 对顶层公共头直接 `continue`，不仅免除跨模块依赖规则，也跳过平台头和构建宏检查。隔离夹具对 `streamcipher.hpp` 注入 `windows.h` 或 `STREAMCIPHER_AESNI` 条件，检查器均错误返回成功；见 `build/audit-20261109/logs/architecture-before.log`。
- 影响：工程检查对公开总入口的实现细节泄漏给出假阴性；不是已证明的运行时密码缺陷。严重度：中（验证可靠性）。
- 处理：总入口仅豁免模块依赖方向规则，仍执行所有公共头通用规则；在现有验证器故障注入测试中加入通过与拒绝用例。范围：检查脚本及其测试，不修改库、接口或密文格式。
- 验收：修复前负例失败；修复后正常总入口通过、两类注入均拒绝；离线构建、13 项测试、独立互操作不低于基线，审查本轮增量。

## 分类与边界

当前实现要求受信任目录、稳定输入，未提供崩溃恢复、恶意目录竞争防护、nonce 分配或跨平台实机证明；这些是现有明确边界而非本轮新缺陷。单对象并发使用不受支持。测试包含标准 GCM 向量、错误认证保留目标、分块、长度及 CLI 回归，独立 cryptography 比对检验 CTR/GCM 字节格式。其余仅凭偏好不能构成修改理由。

审计记录（未发现足以安排其他改造的证据）：

| 范围 | 可定位依据及判断 | 影响与验收 |
|---|---|---|
| 依赖与职责 | `docs/architecture.md`、`scripts/check_architecture.py`、`src/stream/{stream,pipeline}.cpp`：核心状态与原地适配、顺序 I/O 分离；现有单库决策不变 | 通用头检查有 A01；构建隔离编译公共头并运行依赖检查。检查器是模式匹配，不能证明不存在所有间接依赖或循环 |
| 数据和认证 | `src/core/cipher.cpp`、`src/core/parameters.cpp`、`src/io/output_transaction.hpp`：容量先检查；文件验签及输入检查成功后发布；`tests/test_pipeline.cpp` 覆盖篡改、回调失败和目标保留 | 无新缺陷证据；标准向量、互操作、失败路径测试保持通过 |
| 生命周期与并发 | `src/detail/wipe_guard.hpp`、`src/stream/pipeline.cpp`：临时缓冲清理，重入保护和回调快照；并发和恶意目录不属支持范围 | 延续现有边界，回调异常和目标保留回归通过 |
| 构建与测试 | `tests/CMakeLists.txt`、`scripts/build.ps1`：离线来源、头隔离编译、测试和安装消费检查；`tests/test_verification.py` 有优化模式故障注入 | 本轮真实运行结果写入状态；没有独立类型检查工具目标，平台测试局限 Windows x64 |
| 重复与抽象 | `src/core/cipher.cpp` 和 `src/stream/stream.cpp`：流层保留字节计数以满足公开接口，密码状态集中于核心；无证据支持新增层次或删除公共 API | 保持已有边界，不依据风格实施变更 |
