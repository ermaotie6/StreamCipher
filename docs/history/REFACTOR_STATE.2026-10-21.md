> 历史归档：保留当时的结论与命令，不代表当前状态。当前文档见 [历史索引](README.md)。

# 重构执行状态

日期：2026-10-21；分支：codex/modernize-20261021；阶段：本轮确定范围全部完成、验收通过。下一项任务：无必需工作；新增范围须有新的实质证据。

## 恢复入口

先读 AGENTS.md、REFACTOR_PLAN.md，再读本文。禁止覆盖现有未提交修改。HEAD 为542a4be，不代表本轮起点；本轮起点为 build/refactor-20261021/baseline.zip（211文件，含用户新增文件）。SHA256、初始分支、状态、tracked.patch 同目录。新分支创建因沙箱 Git 引用写限制首次失败，经自动审批提升权限后成功；无远程操作。

## 已执行与原始结果

- git status --short / git branch --show-current / git log -5 --oneline：原分支 fix/correctness-and-safety，大量未提交改动；已完整快照。
- 阅读当前核心、流/文件、事务、内存、SIMD、CLI、CMake、构建脚本、架构检查及历史审查/交付说明；入口、状态和边界见计划。
- ctest --test-dir build/delivery-ninja --output-on-failure -j 8：12/12；这是旧目录结果。
- powershell -File build/refactor-20261021/verify.ps1：本轮新目录离线 Release 配置成功、163步构建成功、CTest 12/12；日志 baseline-release-{configure,build,tests}.log。MSVC环境由 vswhere/VsDevCmd 加载，Catch2 使用 build/baseline/_deps/catch2-src，下载关闭，基准关闭。
- python build/refactor-20261021/probe_checks.py：坏 CLI 模拟按预期退出1；python -O 同脚本：错误退出0、打印成功。assert-normal.log / assert-optimized.log 为修复前证据。

## 当前工作与下一步

R03 建档、快照和恢复信息已完成。

R01 已完成：两个脚本的11+5条 assert 条件和既有错误消息均保留，改成显式 if/raise AssertionError；无新增通用测试框架。tests/test_verification.py 用标准库故障注入验证两个脚本在普通、-O、PYTHONOPTIMIZE=1下拒绝坏退出码/坏数据（12组合），注册进 CTest，无新增依赖。模拟 oracle 仅用于检测能力测试。

- python tests/test_verification.py 修复前退出1（8组合误报成功），r01-before.log；修复后退出0，r01-after.log。
- python tests/test_cli.py build/refactor-20261021/release/apps/scipher.exe：通过，r01-cli.log；python -O 同脚本：通过，r01-cli-optimized.log。
- R01 Diff 已复核：原16个条件不变，仅取消解释器优化对校验的影响，生产代码不变。真实独立互操作也已验收，见下表。

R02 已完成：新增256值×128字节位置×正逆两方向的表示对比测试（65,536断言），不依赖正逆抵消。修改前运行 verify.ps1 -Phase r02-before：构建/13项测试全部通过；随后将拆位/组位/临时数据清理集中到匿名命名空间内 substitute_bytes 模板，两个公开入口分别选择 gf::sbox/gf::inv_sbox。未改变索引、循环、清理范围、公共头或 ABI，未引入动态分派。verify.ps1 -Phase r02-after：构建/13项测试全部通过；日志 r02-{before,after}-release-*.log。

## 最终验收证据

所有下列日志位于 build/refactor-20261021/，均为本轮实际运行。verify.ps1 和 sdkcheck.ps1 是同目录的本地复现驱动，不属于产品接口。MSVC x64、Ninja、C++20；依赖下载关闭，Catch2 使用已有本地源码。

| 命令/检查 | 结果 | 日志/证据 |
|---|---|---|
| powershell -File build/refactor-20261021/verify.ps1 -Phase accepted -Variant release | 配置/构建成功；13/13 CTest | accepted-release-{configure,build,tests}.log |
| 同命令 -Variant software（SIMD/AESNI关闭） | 配置/构建成功；13/13 | accepted-software-*.log |
| 同命令 -Variant debug | 配置/构建成功；13/13 | accepted-debug-*.log |
| 同命令 -Variant shared | 配置/构建成功；13/13 | accepted-shared-{configure,build,tests}.log |
| 同命令 -Variant asan | 配置/构建成功；13/13；无消毒器错误 | accepted-asan-*.log |
| powershell -File build/refactor-20261021/sdkcheck.ps1 -Phase accepted -Variant release（及 shared） | 安装成功；安装后真实CLI通过；独立 find_package 消费项目配置/构建成功，各1/1 | accepted-{release,shared}-{install,installed-cli,consumer-configure,consumer-build,consumer-tests}.log |
| python tests/check_interop.py build/refactor-20261021/release/apps/scipher.exe | 真实 cryptography，CTR100+GCM100，全字节输出及双向解密通过 | final-release-interop.log |
| python -O tests/check_interop.py 同路径 | 真实独立互操作200/200，优化模式检查生效 | accepted-optimized-interop.log |
| Python验证器故障注入 | 普通/-O/PYTHONOPTIMIZE=1，两个脚本、坏退出码/坏数据12组合均正确拒绝 | CTest verification；r01-before.log（修复前8失败）/r01-after.log |
| 公共头隔离编译/架构检查 | 13公共头成功；依赖规则通过 | 构建日志；CTest architecture |
| python build/refactor-20261021/audit_increment.py | 原16条断言条件AST完全一致；无原文件丢失；公共头零变化 | increment.json / increment.patch |
| git -c core.safecrlf=false diff --check；Python源码解析 | 空白检查退出0；4个Python文件语法通过 | diff-check.log；final-audit.log |

最后增加的 array 显式包含和脚本说明已由 accepted 系列构建/测试覆盖；没有运行时修改发生在这些验证之后。7个C++测试套件共61用例、139,499断言（原73,963+新增65,536），其余为3个诊断、2个Python集成和1个架构检查，共13项CTest。

## 最终增量复核（实现后单独阶段）

复核者：本次执行者；这是单独的维护者视角复核，不是独立人员或子代理签字。已读取 baseline.zip → 最终的完整增量，避免将用户原有修复当作本轮变更。

- 只修改5个原文件，新增3份持久文档和1个故障注入测试；原211文件中的206个字节不变，无删除。公共头/CLI生产源码/文件协议/参数契约均未修改。
- bitslice.cpp：两个公开入口保留，私有模板选择固定字节函数；循环/索引/临时数组/WipeGuard存储寿命不变，无动态函数选择、外部依赖或新公共符号。
- Python：通过 AST 将基线11+5个条件与最终 if/raise 内条件逐一比较，完全一致；保留原有带消息断言的消息，原无消息断言补充条件说明。负例证实不是仅语法替换。
- 新测试：真实算法验证与故障模拟职责明确；故障测试不要求 cryptography，不把 mock 当互操作证明；CTest 未删除或放宽既有检查。位切片特征先验证原实现，再验证重构结果。
- 复核调整：还原 check_interop.py 的原CRLF格式，补充 test_aes.cpp 的直接 array 包含。以上调整之后已完成最终验收。无证据支持的阻塞发现。

恢复时用 baseline-manifest.json/increment.json 核对文件是否又被编辑。需要撤销本轮时，仅对确认未再变化的5个修改文件从 baseline.zip 恢复，并人工处理本轮新增4文件；不要对整个工作区执行 reset/clean。原始Git状态、HEAD、分支及补丁均保存，当前未提交、未推送。

## 分类与边界

- 已修复：R01 验证Bug；已收敛：R02重复编排、R03恢复记录。既有正确测试预期均保留。
- 本轮已知高严重程度未解决问题、阻塞项、原有基线检查失败、新引入失败：均无。
- 本轮未执行：性能排名/完整基准、重新ZIP打包、部署；这些不属于本轮代码修改验收范围。静态/共享安装消费已验证，不引用历史包作为本轮产物。
- 平台与契约边界：当前仅 Windows x64；无 Linux/macOS/ARM 实机、无完整侧信道证明、无恶意目录竞争防护和崩溃恢复保证；单对象非并发，密钥/nonce唯一性由调用者管理。保留现有说明，不计作已解决能力。
- 完成条件：范围内问题处置完毕；边界保持；五配置无新增失败；独立互操作与关键异常回归通过；最终Diff复核完成；三份文档与实际一致。本轮到此停止。
