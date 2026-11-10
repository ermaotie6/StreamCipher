# 仓库清理与文档核对（2026-10-21）

> 以下原记录属于2026-10-21；2026-11-10复核及本轮结果见文末，勿将旧测试结果当作本轮验证。

> 原工作区的 `trace_log/` 已移出源码目录，以下关于其位置的叙述保留当时状态；原始日志不随源码分发。

状态：本轮清理、文档整合和本地验收已完成。仅本地操作，不引入架构或协议变更；未提交、未推送、未部署。

## 基线与恢复

起点为 codex/modernize-20261021 的未提交工作区，HEAD 542a4be 不能表示本次起点。独立分支 codex/repository-cleanup-20261021。215个文件原始字节、SHA256、Git状态和原分支已保存至本地 build/cleanup-20261021/{baseline.zip,baseline-manifest.json,status.txt,branch.txt,tracked.patch}；逐文件清单 inventory.tsv。215文件包含114份原始日志，不能把历史未提交修改混成本轮成果。

所有删除、移动和内容合并均以快照为回滚依据。需要撤销时先比较本轮增量哈希，只恢复确认没有后续用户编辑的具体文件，禁止 reset/clean 或覆盖整个工作区。未知未跟踪文件不删除。

## 文件分类与证据

此表覆盖需要管理的全部文件组；不把没有直接调用的公共API、教学代码或诊断工具自动判作无用。

| 对象 | 分类 | 证据与处置 |
|---|---|---|
| LICENSE、公共 include/、实际运行 src/（除下两项）、apps/ | KEEP | CMake target_sources、公开头/工厂、CLI入口可定位；无运行时修改 |
| src/memory/pool.cpp、src/memory/span_utils.cpp | DELETE | Git已跟踪；文件仅include和空命名空间，无实例化/定义；顶层CMake未列入，脚本也未调用，运行实现均在hpp。全局出现仅历史说明。删除两个空占位，不删公共头 |
| tests/全部（含bs_debug、bs_debug2、sizes） | KEEP | tests/CMakeLists.txt注册3个diagnostic、7套C++测试、architecture/verification/cli；consumer是独立消费入口，互操作脚本有独立oracle用途 |
| examples/、docs/examples/、benchmarks/ | KEEP | 独立的CTR教学程序、4个SDK消费示例、Google Benchmark目标；用途不同，不因重复加密操作而删除 |
| cmake/、CMakePresets.json、CMakeLists.txt | KEEP/UPDATE | 库导出、架构探测、六配置五测试预设；只调整文档安装清单，使新导航在安装包中也完整 |
| scripts/build.sh、benchmark.sh、check_architecture.py | KEEP | 明确构建/测速/依赖检查入口；Bash仅做本机可执行的语法核对，不冒称POSIX实机通过 |
| scripts/build.ps1 | UPDATE | 原日志写入trace_log，导致生成文件混入历史文档；改为所选BuildDirectory/logs并创建目录，其他工作流保留，实际完整离线交付验证 |
| README.md | UPDATE | 原有错误规模估计、旧报告作“当前结果”、不完整目录、重复构建/API说明；改为功能/目录/可运行快速开始及文档主入口 |
| docs/user-guide.zh-CN.md | MERGE/UPDATE | 原约69KB，重复架构/API/源码索引，并绑定旧分支；保留构建/CLI/SDK/测试/排错的权威说明，将算法和接口委托给architecture/api |
| docs/architecture.md | MERGE/UPDATE | 接收implementation与file-by-file的有用职责/算法信息，保留既有架构与威胁边界，增加当前SubBytes共享编排说明 |
| docs/implementation.md、docs/file-by-file.md | MERGE | 当前短文与architecture/API/guide重复。信息并入architecture后删除两个重复入口；原字节在本次快照，早期长文仍在history |
| docs/api.md | UPDATE | 以13个公共头为签名依据；整合末尾“新增契约”，补齐遗漏SIMD函数、标签寿命、池内存大小/对齐和异常边界，避免复制完整头文件 |
| docs/delivery.zh-CN.md | UPDATE | 保留打包操作，移除“本轮产物”指向10月14日旧包及12测试结论；区分源码、SDK、构建日志与本轮验证 |
| docs/architecture-review.zh-CN.md、docs/bugfix-report.md | ARCHIVE | 有缺陷复现和设计处置历史价值，移至docs/history同名文件，加历史标记，不把当时7/9/12项结果改写成新结果 |
| REFACTOR_PLAN.md、REFACTOR_STATE.md | ARCHIVE | 上一轮已完成且无下一任务；移到docs/history/REFACTOR_{PLAN,STATE}.2026-10-21.md，保留恢复证据；AGENTS更新阅读入口 |
| docs/history/*.pre-architecture.md | ARCHIVE | 已标记过时但存在错误相对链接；保留历史正文，修复导航和自动锚点，不作为当前实现依据 |
| docs/experiments/sbox-circuit.md | ARCHIVE/KEEP | 明确未验证电路，未编译；研究可追溯价值，保留且不启用 |
| docs/decisions/0001-architecture-boundaries.md | KEEP/UPDATE | 单库与有限文件事务决策仍有效；修复历史报告路径并去掉阶段性措辞 |
| trace_log/*.md | ARCHIVE | 9月至10月14日过程记录，有失败处置证据；保留原位置避免大规模挪动，索引标为历史并修复链接 |
| trace_log/*.log、delivery-final-artifacts.json | REVIEW/本地保留 | 基线中为未跟踪历史原始输出；虽然部分字节相同，但不同场景记录不能仅凭hash相同删去。保留文件、加入精确忽略；不能独立确认每份输出来源，不改写其内容 |
| build/已有缓存、产物、前轮快照；空.claude/ | REVIEW/本地保留 | build已忽略，含用户缓存和可恢复快照；没有为了腾空间批量清理。空.claude用途未知保留 |
| .gitignore、AGENTS.md | UPDATE | 添加Python缓存、可执行/调试产物、精确历史日志忽略；维护当前文档入口和工程约束 |

仓库内未发现CI、容器配置、数据库迁移或依赖锁文件；不据此新增部署服务。没有凭风格删除公开类型、实验档案、安全配置或有效测试。

## 文档分工

- [README](../../README.md)：项目入口与最短运行步骤。
- [开发使用](../user-guide.zh-CN.md)：工具链、构建选项、CLI、SDK消费、验证与排错。
- [架构](../architecture.md)：职责、数据流、算法实现选择和资源/信任边界。
- [API](../api.md)：公开头位置、参数、状态、返回值和异常；签名仍以头文件为准。
- [打包](../delivery.zh-CN.md)：本地安装、SDK与ZIP验证；本项目没有服务端部署。
- [历史索引](README.md)：历史报告、已完成重构和原始过程资料。

## 清理结果

- 删除两个未参与构建的空源文件；合并并删除两个重复文档入口。只有这4个文件被实际清除。
- 4份报告/完成记录移动到docs/history并修复导航；旧版本长文、电路实验、历史过程资料保留。所有现行入口已更新，不新增架构层次或删减测试。
- README、开发使用、架构、API、打包各自维护明确主题；去掉失实规模估计、旧分支绑定、过时“当前产物”和重复源码/API粘贴。
- 原始114份日志及1份旧摘要文件均保留原字节，只加入精确忽略；新生成日志在构建目录的logs/，不会继续污染trace_log。
- CMake只扩充文档安装清单（README所链接的AGENTS/清理记录/许可证），库编译、链接、导出及测试配置未改动。PowerShell仅改变生成日志归属并创建目录。

## 验证结果

清理前：ctest --test-dir build/refactor-20261021/release --output-on-failure -j 8，13/13，baseline-tests.log。

所有本轮原始输出保存到build/cleanup-20261021/，下表日志均为本次执行；不将上一轮成功结果重复计入。

| 检查/实际命令 | 结果与证据 |
|---|---|
| README中3个PowerShell命令块 | 库/CLI构建、帮助、GCM往返SHA256一致、开发构建/13项测试通过；readme-commands.log。开发构建预先用本地Catch2配置缓存，未验证在线下载 |
| 开发文档的仅库命令 | build/library配置/构建通过，无开发依赖；同上日志 |
| powershell -ExecutionPolicy Bypass -File scripts/build.ps1 -Variant release -BuildDirectory build/cleanup-20261021/release -Offline -Catch2Source build/baseline/_deps/catch2-src -BenchmarkSource build/fixed/_deps/google_benchmark-src -Interop | 完整189步构建（含基准、示例、13公共头）、13/13测试、真实cryptography互操作200/200；静态SDK安装、安装后CLI、消费1/1、ZIP解包CLI与4个示例全部成功；release/logs/delivery-release-*.log，full-driver.log |
| 同脚本 -Variant shared -BuildDirectory build/cleanup-20261021/shared（同样离线源码参数，不加Interop） | 共享库完整构建、13/13测试、安装后CLI、消费1/1、ZIP解包CLI与4示例全部成功；shared/logs/delivery-shared-*.log，shared-driver.log |
| python build/cleanup-20261021/check_docs.py | 源码26份Markdown、106个本地文件/锚点链接，0错误；docs-source.log。安装目录及解包文档使用同一检查器，均0错误；docs-packages.log |
| python scripts/check_architecture.py；Python源码解析 | 依赖规则通过，4个Python文件语法通过；static-checks.log |
| PowerShell AST；Git附带bash -n scripts/build.sh scripts/benchmark.sh | 两类脚本语法通过；static-checks.log。没有将其描述为Linux/macOS实机运行 |
| rg搜索删除项、基线SHA256比对、git diff --check | 无构建/脚本调用残留；运行源/公共头/有效测试及示例原字节不变；历史原始日志不变；无空白错误；final-audit.log及increment.json/increment.patch |

Release与shared的ZIP、安装SDK以及解包验证目录均在各自构建目录，未发布远程。更新本记录后重新安装/打包并检查文档，使包内记录与源码一致。没有变更密码实现，因此没有为本次文档清理重复宣称Debug/软件/ASan的新验收；这些配置上轮证据仍按历史时点保留。

## 最终复核与剩余事项

实施后另作维护者视角复核（同一执行者，不冒称独立人员签字）：按本次baseline而非HEAD检查全部增量。删除清单精确限定4文件；另4个旧路径都有归档目标。确认源码声明、CLI帮助、模式长度、候选明文、进度/发布、池存储量、CPU能力与构建开关区别均与当前实现一致；历史表格保留当时数字并明确标记为历史。

包级复核发现历史报告指向本地原始日志的链接不能随仅Markdown的SDK携带，已改为明确的本地证据路径文字，保留日志本体；所有真正导航链接在源码和包内均可解析。未发现阻塞性新问题。

保守保留项：已有build缓存/旧包/快照、未知用途的空.claude目录、未能逐份独立确认来源的历史原始输出；没有执行批量删除。外部URL可达性、在线依赖下载、Linux/macOS/ARM运行、生产部署和密码侧信道性质未在本轮验证。无需要额外授权而未完成的必需清理项。

恢复所需文件在本页“基线与恢复”所述目录；increment.json记录本轮修改/删除/新增的具体路径和哈希。清理已达到本次范围，后续不因纯风格偏好继续调整。

## 2026-11-10：仓库收尾复核

基线为 `codex/audit-20261109` 的未提交工作区；本轮切换至本地 `codex/repository-final-20261110`，未提交、推送或部署。起点状态、非忽略文件SHA256和已跟踪补丁保存于 `build/repository-final-20261110/logs/`；本轮触及的文档原件保存于 `build/repository-final-20261110/before/`。恢复前须核对文件是否又被编辑；不得恢复整个工作区。

| 对象 | 分类 | 当前证据与处置 |
|---|---|---|
| 许可证、CMake、公共头、src、apps | KEEP | 顶层及子目录构建目标、安装清单和公开接口均可定位；不以缺少直接引用删除公共接口 |
| tests、benchmarks、examples、docs/examples | KEEP | 测试和诊断由tests/CMakeLists.txt注册，消费项目、互操作和示例各有用途；基准包含流矩阵和AES路径 |
| scripts、cmake、CMakePresets.json | KEEP | 构建、离线交付、性能、架构检查和导出入口；平台行为不由Windows测试推断 |
| README、开发文档、历史索引 | UPDATE | 增加材料对照入口、修正性能及历史记录的时点和工作区位置；保留既有权威分工 |
| 架构、API、打包文档、决策记录 | KEEP | 对照公共头、实现和CMake职责；当前无证据支持架构变更 |
| docs/history、trace_log Markdown、S-box实验、材料对照记录 | ARCHIVE/KEEP | 历史缺陷、设计、测量和未验证实验有追溯价值；不作为当前能力或新测试结果 |
| 根目录 REFACTOR_PLAN.md、REFACTOR_STATE.md | REVIEW/KEEP | 未跟踪用户原件，内容为2026-11-09审计，不同于docs/history的2026-10-21记录；保留原字节、标明归属，不擅自移动或删除 |
| build、trace_log原始日志/JSON、.claude | REVIEW/KEEP | 本地缓存、历史原始输出和未知用途目录；保留。忽略规则已覆盖build与历史原始输出，未发现需要扩大忽略规则的证据 |
| 可确认新无用文件 | DELETE：无 | 旧记录中的4项删除已经是本轮基线，不能重复计作本次删除；本轮没有对未知来源或有效文件做删除 |

### 本轮验证与复核

- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build.ps1 -Variant release -BuildDirectory build/repository-final-20261110/release -Offline -Catch2Source build/baseline/_deps/catch2-src -BenchmarkSource build/fixed/_deps/google_benchmark-src -Interop`：Windows x64、MSVC 19.44，离线构建、13/13测试、CTR/GCM各100个独立互操作、安装CLI、消费项目、ZIP解包CLI及四个示例通过；分步日志在该构建目录 `logs/`。
- README三个命令块在本轮独立 `quickstart`、`dev` 目录执行：CLI构建和help、GCM往返哈希一致、开发构建及13/13测试通过。为离线执行额外指定本地Catch2和关闭下载；原命令的在线下载未验证。执行记录在 `build/repository-final-20261110/logs/readme-commands.log`，逐条命令在 `build/repository-final-20261110/readme-check.ps1`。
- `python build/cleanup-20261021/check_docs.py .`：29份Markdown、109个本地文件/锚点链接、0错误；3个外部链接未检查。检查器为模式匹配，不能保证覆盖所有Markdown形式。`python scripts/check_architecture.py` 和 `python -O tests/test_verification.py` 通过。日志在 `build/repository-final-20261110/logs/`。
- 实施后以维护者复核视角，依据本轮SHA256清单和原件而非HEAD核对增量；对照公共参数头、文件编排/事务、CMake安装及测试入口复查文档，保留已跟踪历史删除和未跟踪用户文件的基线状态。此复核由同一执行者完成，不冒称独立人员签字。最终文件差异、链接检查和打包文档检查保存在上述日志目录。

本轮未运行Linux/macOS/ARM、在线下载、外部链接、共享库或侧信道实测；既有历史记录保留各自时点。没有发现足以安全删除的新文件，也没有对旧测试或旧包冒称本轮结果。

## 2026-11-11：提交前整理

根据提交准备请求，将根目录的2026-11-09审计计划和状态归档到 `docs/history/REFACTOR_PLAN.2026-11-09.md`、`docs/history/REFACTOR_STATE.2026-11-09.md`，原字节与2026-11-10起点清单的哈希一致；历史索引已更新。上节保留2026-11-10当时的处置，不代表本次归档前后状态。README去除只适用于未提交工作区的临时说明；材料评估注明外部材料未随仓库分发，移除本机绝对路径。`.gitignore` 增加本地工具工作树目录，已有build和原始日志忽略规则保留。保留构建缓存、历史日志和快照，不将本地生成物加入提交。

本轮原件保存在 `build/precommit-20261111/before/`，初始状态保存在同目录 `logs/`；恢复前先确认没有后续编辑。

实际执行 `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build.ps1 -Variant release -BuildDirectory build/precommit-20261111/release -Offline -Catch2Source build/baseline/_deps/catch2-src -BenchmarkSource build/fixed/_deps/google_benchmark-src -Interop`：Windows x64/MSVC离线构建、13/13测试、200/200独立互操作、安装消费与解包示例通过；逐步日志在构建目录的 `logs/`。归档前后SHA256一致；`python build/cleanup-20261021/check_docs.py .` 检查29份Markdown和111个本地链接无错误，外部链接未验证；`git diff --check` 和目标忽略规则检查通过。以上不构成Linux或其他平台的新验证。
