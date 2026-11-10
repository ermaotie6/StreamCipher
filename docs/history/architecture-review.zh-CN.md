> 历史归档：保留当时的结论与命令，不代表当前状态。原始日志不随源码分发。当前文档见 [历史索引](README.md)。

# StreamCipher 架构审查与优化台账

审查日期：2026-09-22。基线为本地 `fix/correctness-and-safety` 分支的上一轮修复工作区，原始 Git 提交为 `542a4be`。所有操作在当前工作区完成；没有提交或推送。

最终交付复核：2026-09-23，最后源码增量构建成功，CTest 9/9 通过，见当时的最终验证日志。

本次提出 **122 条建议**。建议是具有独立验收条件的工程改进或设计决策，不把它们描述为 122 个独立漏洞。下表中的“实施”指代码/构建/测试调整，“契约”指修正文档或明确调用约束，“保留验证”指基线设计已合理且本轮需要回归，“条件决策”指当前范围之外的扩展，经评估不在本轮引入。

当前状态：本轮实施和验收完成。89 项代码/构建/测试调整、13 项契约与文档调整、10 项现有合理设计通过回归、10 项条件扩展形成明确取舍。P1 为正确性、状态与资源边界；P2 为维护/交付；P3 为条件性扩展。

## 一、职责与依赖边界

| 编号 | 优先级 | 建议 | 代码依据/动机 | 处置与验收入口 | 状态 |
|---|---|---|---|---|---|
| A001 | P1 | 抽出独立模式参数契约 | core/cipher.hpp 原本同时声明参数和多态上下文 | core/parameters.hpp/.cpp | 实施 |
| A002 | P1 | 移除 CipherCtx 对 AES 实现头的传递依赖 | cipher.hpp 包含 aes.hpp，使抽象泄漏实现 | cipher.hpp；头文件隔离编译 | 实施 |
| A003 | P1 | 移除流接口对 Chunker 等工具的无用依赖 | stream.hpp 包含 span_utils.hpp 但声明未使用 | stream.hpp；依赖检查 | 实施 |
| A004 | P1 | 让文件接口只依赖参数契约 | pipeline.hpp 原本拉入整个流接口 | pipeline.hpp 显式包含 functional | 实施 |
| A005 | P1 | GHASH 应为可独立阅读的私有组件 | cipher.cpp 内同时存在有限域乘法与模式状态机 | src/core/ghash.hpp/.cpp | 实施 |
| A006 | P1 | 统一两个层次的认证比较 | CipherCtx 与 StreamProcessor 重复比较循环 | src/detail/authentication.hpp | 实施 |
| A007 | P1 | 把输出发布事务与密码编排分开 | pipeline.cpp 内含平台重命名及临时目录管理 | src/io/output_transaction.hpp | 实施 |
| A008 | P1 | 隔离 AES 后端选择与标量算法 | aes.cpp 同时调用硬件层，硬件层又回调标量 | src/core/aes_dispatch.cpp | 实施 |
| A009 | P1 | 停止编译仅占位的模板源文件 | src/memory/pool.cpp、span_utils.cpp 没有运行时定义 | CMake target_sources 移除占位 TU | 实施 |
| A010 | P1 | 将应用解析与业务执行分离 | apps/main.cpp 混合解析、文件处理和测速 | apps/options.cpp、commands.cpp、main.cpp | 实施 |

## 二、公开契约与错误语义

| 编号 | 优先级 | 建议 | 代码依据/动机 | 处置与验收入口 | 状态 |
|---|---|---|---|---|---|
| A011 | P1 | 以 ModeSpec 统一模式能力和限额 | 标签长度、首计数器、限额分散在 core/stream/pipeline | mode_spec；contract 测试 | 实施 |
| A012 | P1 | 提供加密输出长度查询 | 调用方手写 GCM +16 容易容量错误 | encrypted_size；边界测试 | 实施 |
| A013 | P1 | 提供解密载荷长度查询 | 文件和内存重复截断标签计算 | decrypted_size；空/短消息测试 | 实施 |
| A014 | P1 | 构造时拒绝不支持的算法模式 | FilePipeline 到打开文件时才验证 | validate_parameters；构造失败测试 | 实施 |
| A015 | P1 | 为方向提供强类型入口 | bool true/false 在 GCM 调用点难以审阅 | Direction 重载；旧接口等价测试 | 实施 |
| A016 | P1 | 拒绝伪造的 Direction 枚举值 | 新增强类型也可能经 static_cast 构造非法值 | 两个工厂重载显式验证 | 实施 |
| A017 | P1 | 保留旧 bool 工厂兼容入口 | 直接替换会破坏现有调用代码 | 保留原签名；contracts 对比 | 实施 |
| A018 | P1 | 提供可按类型捕获的认证失败 | 此前调用者只能解读 runtime_error 文本 | AuthenticationError 继承 runtime_error | 实施 |
| A019 | P1 | 初始化抽象上下文的元数据 | 基类 algo_/mode_ 原本未初始化 | CipherCtx 成员默认值 | 实施 |
| A020 | P1 | 禁止流处理器对象复制 | 具有消息状态的抽象对象不应暗示可复制 | StreamProcessor 删除复制操作 | 实施 |

## 三、敏感状态生命周期

| 编号 | 优先级 | 建议 | 代码依据/动机 | 处置与验收入口 | 状态 |
|---|---|---|---|---|---|
| A021 | P1 | 提供明确的字节覆盖原语 | 原先依赖普通对象析构释放敏感数据 | memory::secure_zero | 实施 |
| A022 | P1 | 用 RAII 覆盖异常退出的暂存数据 | 手动清理容易遗漏抛异常路径 | src/detail/wipe_guard.hpp | 实施 |
| A023 | P1 | 销毁模式上下文时覆盖扩展密钥 | AesCipherCtx round_keys_ 普通数组析构 | AesCipherCtx 析构 | 实施 |
| A024 | P1 | 销毁上下文时覆盖缓存密钥流与标签状态 | keystream_/pending_/j0_ 等长期留在已释放内存 | AesCipherCtx 析构 | 实施 |
| A025 | P1 | 清理 GHASH 密钥与累积状态 | 独立 GHASH 组件持有密钥相关状态 | GHash 析构；禁止复制 | 实施 |
| A026 | P1 | 清理 GHASH 乘法的临时工作块 | multiply 中栈上 v/z 含派生秘密 | GHash::update WipeGuard | 实施 |
| A027 | P1 | 清理标量及位切片包装函数的轮密钥 | AES ECB/批量入口局部展开密钥 | aes.cpp WipeGuard | 实施 |
| A028 | P1 | 清理硬件与软件分派的轮密钥副本 | aesni.cpp 与 aes_dispatch.cpp 有额外副本 | 分派路径 WipeGuard | 实施 |
| A029 | P1 | 清理一次性认证解密的暂存明文 | vector 释放不等于覆盖，认证失败也须清理 | decrypt_one_shot WipeGuard | 实施 |
| A030 | P1 | 清理文件缓冲和 FilePipeline 原始密钥 | 文件处理和 PImpl 析构无覆盖 | pipeline.cpp buffer guard 与 Impl 析构 | 实施 |

## 四、文件操作、事务与回调

| 编号 | 优先级 | 建议 | 代码依据/动机 | 处置与验收入口 | 状态 |
|---|---|---|---|---|---|
| A031 | P1 | 对每次操作建立配置快照 | 回调可修改传入 config，原实现持有引用 | PipelineConfig settings 副本 | 实施 |
| A032 | P1 | 复制生效回调后再开始执行 | 回调替换自身可能销毁正在执行的闭包 | 独立 progress 副本；自替换回归 | 实施 |
| A033 | P1 | 拒绝同一管道的递归操作 | 回调中重入会使状态和目标发布难以推理 | running + RunGuard；重入测试 | 实施 |
| A034 | P1 | 异常退出必须重置忙碌状态 | 简单 bool 标记容易使对象永久不可用 | RunGuard；失败后重用测试 | 实施 |
| A035 | P1 | 明确禁止输出符号链接 | rename 对链接和目标的语义跨平台易误用 | preflight is_symlink 拒绝 | 实施 |
| A036 | P1 | 提前拒绝非普通输出文件 | 原先处理完载荷才发现目标为目录 | preflight is_regular_file | 实施 |
| A037 | P1 | 事务类不暴露可任意操纵的 ofstream | 调用者能绕过关闭和发布约束 | 私有 stream、write/publish 接口 | 实施 |
| A038 | P1 | 在 POSIX 创建时设置暂存目录权限 | 先 mkdir 再 chmod 存在暴露窗口 | mkdir(...,0700)；POSIX 待平台验证 | 实施 |
| A039 | P1 | 区分进度到 100% 与发布成功 | 回调先于标签验证和重命名 | 接口注释与架构文档 | 契约 |
| A040 | P1 | 限定回调中的对象生命周期操作 | 回调内销毁/移动正在执行的对象不能靠快照保证 | 禁止该行为的明确前置条件 | 契约 |

## 五、构建隔离

| 编号 | 优先级 | 建议 | 代码依据/动机 | 处置与验收入口 | 状态 |
|---|---|---|---|---|---|
| A041 | P2 | 嵌入其他工程时默认只建立库 | 原有四组开发目标全部默认 ON | STREAMCIPHER_TOP_LEVEL 默认值；consumer 测试 | 实施 |
| A042 | P2 | 不覆盖父工程的 C++ 标准设置 | 目录全局设置标准造成依赖副作用 | target_compile_features；consumer 标准断言 | 实施 |
| A043 | P2 | 基准默认关闭 | 普通用户构建不应必须下载 Google Benchmark | STREAMCIPHER_BUILD_BENCHMARKS=OFF | 实施 |
| A044 | P2 | 优先复用已存在的依赖 target | 重复拉取 Catch2/Benchmark 导致重复 target | if(NOT TARGET) 检查 | 实施 |
| A045 | P2 | 优先查找已安装测试依赖 | 原先只有 FetchContent 路径 | find_package 版本约束 | 实施 |
| A046 | P2 | 使外部依赖下载可显式禁用 | 离线与嵌入构建需要可预测失败方式 | STREAMCIPHER_FETCH_DEPENDENCIES | 实施 |
| A047 | P2 | 依赖构建选项限定在函数作用域 | 不能通过设置 BUILD_SHARED_LIBS 改变宿主 | 两个 dependency 函数 | 实施 |
| A048 | P2 | 移除依赖选项的 FORCE cache 修改 | Benchmark 测试选项污染父工程缓存 | 局部普通变量及 CMP0077 | 实施 |
| A049 | P2 | 对旧依赖 CMake 明确 option 策略 | 旧 cmake_minimum_required 清除普通变量 | 函数内 CMAKE_POLICY_DEFAULT_CMP0077 | 实施 |
| A050 | P2 | 测试也使用导出的命名空间 target | 内部链接应覆盖真实消费者的用法 | streamcipher::streamcipher | 实施 |

## 六、发布、配置与公共表面

| 编号 | 优先级 | 建议 | 代码依据/动机 | 处置与验收入口 | 状态 |
|---|---|---|---|---|---|
| A051 | P2 | 安装包不携带测试/基准依赖 | 此前安装 SDK 时附带第三方库 | 依赖目录 EXCLUDE_FROM_ALL；安装清单检查 | 实施 |
| A052 | P2 | 支持自定义安装头文件目录 | GNUInstallDirs 与硬编码 INSTALL_INTERFACE 不一致 | CMAKE_INSTALL_INCLUDEDIR；自定义路径消费 | 实施 |
| A053 | P2 | 随 SDK 安装许可证 | 此前只安装头文件和库 | share/licenses/streamcipher/LICENSE | 实施 |
| A054 | P2 | 对 0.x 包避免跨次版本兼容承诺 | SameMajorVersion 对 0.x 过于宽泛 | SameMinorVersion | 实施 |
| A055 | P2 | 给共享库添加版本元数据 | 缺少 VERSION/SOVERSION 策略 | target 属性；不宣称 C++ ABI 稳定 | 实施 |
| A056 | P2 | 公共 Vec256 不随构建宏消失 | 软件构建改变可见类型和符号集合 | 稳定声明和软件实现；contracts | 实施 |
| A057 | P2 | 实现开关不向消费方传播 | PUBLIC AESNI/SIMD 宏污染客户端 | PRIVATE definitions；consumer 断言 | 实施 |
| A058 | P2 | SIMD 关闭时也应控制 helper 内联路径 | 源文件仅检查编译器 ISA 宏 | 同时检查 STREAMCIPHER_SIMD | 实施 |
| A059 | P2 | 提供目标级 AddressSanitizer 选项 | 原先需手工拼接全局编译链接 flags | STREAMCIPHER_ENABLE_ASAN | 实施 |
| A060 | P2 | 提供多配置可复现预设 | 不同人手写命令易漏掉软件/共享验证 | CMakePresets.json；6 个配置预设 | 实施 |

## 七、命令行边界

| 编号 | 优先级 | 建议 | 代码依据/动机 | 处置与验收入口 | 状态 |
|---|---|---|---|---|---|
| A061 | P2 | 使解析器无文件副作用 | 参数错误不应触及输出文件 | cli::parse 与 execute 分离 | 实施 |
| A062 | P2 | 统一入口异常和退出码 | 解析散落在 main 的 return/throw 混合 | 小型 main 的统一 catch | 实施 |
| A063 | P2 | 禁止 Options 隐式复制敏感参数 | 解析结构可能重复保存密钥 | Options 删除 copy；仅允许构造移动 | 实施 |
| A064 | P2 | 清理 CLI 解析出的 key/nonce | 原始堆栈字节没有生命周期策略 | Options 析构 secure_zero | 实施 |
| A065 | P2 | 拒绝重复选项消除 last-wins 歧义 | 重复 --key/--mode 可覆盖已审阅参数 | seen 集合；CLI 回归 | 实施 |
| A066 | P2 | 命令只接受属于自身的选项 | 文件选项和基准选项需要隔离 | 解析分支；CLI 反例 | 实施 |
| A067 | P2 | 让用户可控制文件内存分块 | 之前只能修改 CLI 源码 | --chunk-size；正数/溢出校验 | 实施 |
| A068 | P2 | 把进度放 stderr，最终结果留 stdout | 进度干扰脚本解析输出 | commands.cpp；管道契约 | 实施 |
| A069 | P2 | 提供静默进度并限制重复刷新 | 小 chunk 导致每字节刷新终端 | --no-progress；仅百分比改变时刷新 | 实施 |
| A070 | P2 | 基准在计时前分配工作缓冲 | 每轮分配使指标混入堆分配开销 | 重复使用 work；明确仍包含复制/建上下文 | 实施 |

## 八、架构回归验证

| 编号 | 优先级 | 建议 | 代码依据/动机 | 处置与验收入口 | 状态 |
|---|---|---|---|---|---|
| A071 | P1 | 逐个公共头文件独立编译 | 传递 include 隐藏依赖不完整 | streamcipher_header_checks OBJECT | 实施 |
| A072 | P1 | 自动检查公共模块依赖方向 | 文档分层约定缺少可执行门槛 | scripts/check_architecture.py | 实施 |
| A073 | P1 | 阻止私有平台头和路径泄漏到公共接口 | 内部重构易扩大客户端编译依赖 | architecture CTest 规则 | 实施 |
| A074 | P1 | 阻止库反向依赖 CLI 和测试框架 | 应用层与核心不应形成环 | architecture CTest 规则 | 实施 |
| A075 | P1 | 以零分配方式验证消息长度边界 | 计数器上限无法靠分配 64GiB 测试 | contracts 的精确边界和 UINT64_MAX | 实施 |
| A076 | P1 | 验证强类型方向与旧工厂字节一致 | 接口重载不得改变线格式 | contracts encrypt/decrypt 比对 | 实施 |
| A077 | P1 | 验证无 SIMD 时仍有完整公共类型 | 仅默认编译看不到 API 开关问题 | Vec256 contracts；软件矩阵 | 实施 |
| A078 | P1 | 验证认证错误类型且输出保持不变 | 异常分类改动不能削弱原子性 | AuthenticationError contracts | 实施 |
| A079 | P1 | 对异常路径的清理做活对象测试 | 不能读已释放内存来假装验证擦除 | WipeGuard 作用域后检查活数组 | 实施 |
| A080 | P1 | 验证外部消费者而非仅内部 target | 库内部构建无法发现导出/嵌入问题 | tests/consumer 两种模式 | 实施 |

## 九、保持并加强现有正确性约束

| 编号 | 优先级 | 建议 | 代码依据/动机 | 处置与验收入口 | 状态 |
|---|---|---|---|---|---|
| A081 | P1 | 保留独立标准向量作为密码重构门槛 | 实现自洽不等于标准一致 | test_regressions AES/GCM 标准向量 | 保留验证 |
| A082 | P1 | 保留不同分块的加解密等价测试 | 模式状态重构易丢剩余密钥流 | test_regressions 1–33 字节分块 | 保留验证 |
| A083 | P1 | 保留每字节篡改和错密钥/nonce 检查 | 标签比较重构不能放宽验证 | test_regressions 与 test_pipeline | 保留验证 |
| A084 | P1 | 保留一次性函数部分重叠语义 | 重构暂存逻辑可能破坏 memmove 合约 | test_regressions overlap 测试 | 保留验证 |
| A085 | P1 | 保留 finalize/finish 幂等状态机 | 重复完成不应再次 GHASH 长度块 | 既有 lifecycle 测试 | 保留验证 |
| A086 | P1 | 保留输入输出别名保护 | 事务提取不能截断硬链接/同路径源 | test_pipeline aliases | 保留验证 |
| A087 | P1 | 保留异常不替换目标文件的契约 | 原子发布是文件 API 核心价值 | callback/tamper/I/O 失败测试 | 保留验证 |
| A088 | P1 | 保留跨实现互操作检查 | 同一算法实现往返可能共享错误 | tests/check_interop.py 200 个用例 | 保留验证 |
| A089 | P1 | 保持有限内存文件处理 | 不因认证功能将整个文件读入 RAM | pipeline 单块缓冲及磁盘暂存 | 保留验证 |
| A090 | P1 | 保持软件、硬件和共享库验证矩阵 | 单一默认配置无法覆盖分派/导出 | presets + CTest 日志 | 保留验证 |

## 十、文档与运行约束

| 编号 | 优先级 | 建议 | 代码依据/动机 | 处置与验收入口 | 状态 |
|---|---|---|---|---|---|
| A091 | P2 | 用真实依赖图替换过时架构图 | 旧文档把 SIMD/内存描绘为必经层 | docs/architecture.md | 契约 |
| A092 | P2 | 删去全程零拷贝的过度承诺 | 一次性认证解密有 O(n) 暂存 | 架构和手册同步 | 契约 |
| A093 | P2 | 删去无测量的性能超越宣称 | 旧文档宣称克服 OpenSSL 性能瓶颈 | 改为原型和实际路径描述 | 契约 |
| A094 | P2 | 区分代数 S-box 与完整位切片电路 | 旧文档混淆未启用的实验代码 | 实验区隔离和路径说明 | 实施 |
| A095 | P2 | 清楚记录算法/模式/格式支持矩阵 | 枚举或规划不代表当前支持 | 模式能力表；ECB/AAD 明确边界 | 契约 |
| A096 | P2 | 明确 nonce 唯一性责任与复用语义 | FilePipeline 可多次调用但不跟踪全局 nonce | 安全与调用契约 | 契约 |
| A097 | P2 | 区分密码认证与介质持久化 | rename 成功不代表断电后持久 | 事务限制与威胁模型 | 契约 |
| A098 | P2 | 明确源文件稳定性前提 | 当前只能发现长度增长/缩短，不能提供快照 | 并发修改限制 | 契约 |
| A099 | P2 | 明确对象线程安全及回调生命周期 | 独立对象和同一对象并发不同 | 公共注释和架构说明 | 契约 |
| A100 | P2 | 使手册的新 CLI、构建和 API 与代码同步 | 以前文档无新参数且默认基准为 ON | README、API、手册新增变更说明 | 契约 |

## 十一、维护与审查流程

| 编号 | 优先级 | 建议 | 代码依据/动机 | 处置与验收入口 | 状态 |
|---|---|---|---|---|---|
| A101 | P2 | 用自动超时避免测试无限阻塞 | C++ CTest 缺少 timeout | unit 180s/integration 120s/architecture 30s | 实施 |
| A102 | P2 | 给测试贴标签以支持按层检查 | 难以快速选择契约与集成检查 | CTest LABELS | 实施 |
| A103 | P2 | 使构建脚本与调用时的 cwd 无关 | 原脚本 cmake -B 使用当前目录 | scripts/build.sh 显式 -S | 实施 |
| A104 | P2 | 让构建脚本不依赖 Linux 专属 nproc | 脚本在 macOS 上可移植性不足 | cmake --build --parallel | 实施 |
| A105 | P2 | 让基准脚本支持多配置生成器目录 | 原脚本只查单配置可执行路径 | scripts/benchmark.sh 配置参数 | 实施 |
| A106 | P2 | 给敏感清理说明其有限保证 | volatile 覆盖不等于寄存器/交换区全面清除 | secure.hpp 与架构限制 | 契约 |
| A107 | P2 | 为每一项建议记录证据、处置和验收 | 只罗列数量无法审计 | 本台账与 trace_log | 实施 |
| A108 | P2 | 保存失败过程而非只保存最终成功 | 重构的失误也是关键操作记录 | trace_log/004 及后续验证记录 | 实施 |
| A109 | P2 | 为公共 SlabPool 增加显式过度对齐能力 | 通用模板仅保证 max_align_t，无法表达客户需求 | 第三模板参数及回归测试 | 实施 |
| A110 | P2 | 给头文件模板明确所有权和线程约束 | 池不负责对象析构也不是密码秘密容器 | pool.hpp 契约注释 | 契约 |

## 十二、扩展建议的适用条件与取舍

| 编号 | 优先级 | 建议 | 代码依据/动机 | 处置与验收入口 | 状态 |
|---|---|---|---|---|---|
| A111 | P3 | 评估多线程文件管道 | 当前无吞吐需求或认证分块协议支撑 | 保持显式拒绝并行选项；未来先测量再设计 | 条件决策 |
| A112 | P3 | 评估 AAD 和版本化容器格式 | 现有裸 CTR/GCM 格式没有元数据 | 新增格式须单独版本设计；本轮保留字节兼容 | 条件决策 |
| A113 | P3 | 评估 AES-256/其他算法 | 当前用户目标是审查已有 AES-128 架构 | 保留明确的拒绝入口；不加入未测试算法 | 条件决策 |
| A114 | P3 | 评估口令 KDF 与密钥存储服务 | 当前 CLI 接受原始 key，缺少口令产品需求 | 不自行发明 KDF；作为上层集成责任 | 条件决策 |
| A115 | P3 | 评估全局 nonce 自动分配 | 唯一性涉及跨进程持久化和密钥标识 | 保持调用者管理；不能用进程内计数假装解决 | 条件决策 |
| A116 | P3 | 评估 fsync/FlushFileBuffers 持久事务 | 当前 API 承诺成功后发布，不承诺断电恢复 | 未来独立 durability 策略并做故障注入 | 条件决策 |
| A117 | P3 | 评估不可信目录下的句柄相对 I/O | 当前路径检查存在并发命名空间变更边界 | 当前限定受信任目录；开放攻击者目录需专门后端 | 条件决策 |
| A118 | P3 | 评估原生 Windows 私有 DACL 暂存 | filesystem::permissions 不建立完整私有 ACL | 当前要求目标目录私有；未来按服务身份设计 ACL | 条件决策 |
| A119 | P3 | 评估 AES 多块批处理及 PCLMUL GHASH | 逐字节模式循环和软件 GHASH 尚有性能空间 | 先建立受控性能基线；本轮不混入密码优化实验 | 条件决策 |
| A120 | P3 | 评估动态后端注册、插件和多库拆分 | 目前一个算法两个模式，维护开销大于收益 | 采用私有源文件边界和单一导出库；按规模再拆 | 条件决策 |

## 十三、二次审查补充

| 编号 | 优先级 | 建议 | 代码依据/动机 | 处置与验收入口 | 状态 |
|---|---|---|---|---|---|
| A121 | P1 | 目标架构识别必须尊重交叉编译目标 | CMAKE_SYSTEM_PROCESSOR 不能独自表达 VS 平台/macOS 多 slice | DetectArch 优先 generator platform/OSX slices，通用目标禁用 AES-NI；本机验证 x64，其他目标待真机验证 | 实施 |
| A122 | P1 | CLI 在应用边界归一化 Windows Unicode 参数 | 窄字符 main 和默认 path 转换无法可靠处理中文/emoji | wmain→UTF-8→u8path；CLI Unicode 路径往返测试 | 实施 |

## 验收结果

环境：Windows x64、MSVC 19.44.35217、CMake/Ninja。表中日志为当时本地输出，不随源码分发。

| 验证 | 本轮结果 | 证据 |
|---|---|---|
| Release，包含库/CLI/示例/基准 | 构建成功，9/9 CTest | release-tests.log（历史本地输出） |
| Debug | 构建成功，9/9 | debug-tests.log（历史本地输出） |
| 关闭 SIMD 与 AES-NI | 构建成功，9/9，Vec256 API 仍可用 | software-tests.log（历史本地输出） |
| Windows DLL | 构建成功，9/9 | shared-tests.log（历史本地输出） |
| MSVC ASan | 统一源码依赖检测配置后构建成功，9/9 | asan-tests.log（历史本地输出） |
| 核心 C++ 检查数量 | 7 个套件，60 个测试用例，73,963 次断言 | build/architecture/Testing/Temporary/LastTest.log |
| 独立 Python cryptography 互操作 | 200/200，CTR 100 + GCM 100 | interop.log（历史本地输出） |
| 公共头独立编译 | 13 个公共头通过 | release-build.log；streamcipher_header_checks |
| 子目录嵌入 | 保持父工程 C++ 标准、不生成附属目标、不下载依赖；运行 1/1 | consumer-embedded-tests.log（历史本地输出） |
| 安装包消费 | 非默认 sdk-include 目录下 find_package/编译/运行 1/1；无第三方开发库和私有头 | consumer-installed-tests.log（历史本地输出）、install.log（历史本地输出） |
| 最小库 | 禁用全部附属目标及依赖下载，构建成功 | minimal-build.log（历史本地输出） |
| 四个手册示例 | 从安装包独立编译运行通过，文件还原 SHA-256 一致 | 历史本地验证记录 |
| 基准冒烟 | AES fast 与 GCM 场景可执行 | benchmark-aes.log、benchmark-gcm.log；不是性能排名 |
| Shell 脚本 | Git Bash 语法检查通过 | 历史本地验证记录；未冒充 Linux/macOS 实跑 |

## 本轮结论与剩余边界

基于上述代码复查和验证，**在 AES-128 CTR/GCM、顺序文件处理、稳定输入、受信任目录和已测试 Windows 工具链的契约范围内，未再发现本轮尚未处理的架构阻塞问题**。这不是全平台、全威胁模型无问题的证明。所有 122 条建议都已明确处置，不把 10 项条件性扩展计为已实现能力。

仍需明确保留的限制：

1. Linux/macOS/ARM、MinGW 和 POSIX 0700 分支没有本机运行证据；跨平台代码检查不能替代目标平台测试。
2. 文件事务不抵抗攻击者并发替换目录/路径，不提供源文件快照、断电持久化或崩溃恢复；Windows 需私有目录 ACL。此边界见 A117/A118 与 ADR。
3. nonce 唯一性由调用者负责；候选明文暂存可能写入磁盘。字节覆盖不等于清理介质、寄存器、调用者副本或交换区。
4. 未实现 AAD、新容器、并行处理及新算法；这属于明确的产品范围。性能批处理建议未混入此次正确性重构。
5. C++ API 不承诺稳定二进制 ABI；消费方需重编译，直接使用的模块需显式 include。旧 bool API 和本轮前已修复的 CTR/GCM 文件字节格式保持兼容。

工作区保留全部改动和日志；未提交、未推送。
