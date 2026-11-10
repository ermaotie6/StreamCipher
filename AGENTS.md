# 长期工程约束

- 本项目是 C++20 单库 AES-128 CTR/GCM 原型。先读 README.md、docs/history/REPOSITORY_CLEANUP.md 和当前 Git 状态；完成的重构计划/状态保存在 docs/history/，仅按需追溯，不要重新推翻已验证的边界。
- 默认行为保持。公共头、CLI 参数与退出语义、CTR 从 0 起始、GCM 从 2 起始、12 字节 nonce、空 AAD、末尾 16 字节标签均为当前契约。真实 Bug 必须先有复现或独立契约依据。
- 核心状态只在 CipherCtx；StreamProcessor 负责原地适配；FilePipeline 负责顺序 I/O；OutputTransaction 负责暂存和发布。不得绕过认证后发布或错误保留原目标的约束。
- 优先删减重复逻辑；不增加插件框架或多库层次。内部清理临时秘密数据，保留软件回退和运行时 AES-NI 分派。
- 不删除测试、不放宽正确断言、不跳过失败。密码变更须有标准向量或独立实现比对；验证程序不得因 Python 优化模式静默失效。
- 独立 codex/ 分支工作。当前大量未提交改动属于用户基线，禁止 reset、clean、覆盖或将其误报为本次新增修改。恢复仅针对本次触及文件且先核对后续编辑。
- 仅授权本地可回滚操作；不推送、部署、读取生产数据或执行不可逆迁移。逐单元更新状态，记录真实命令、结果及环境限制，不用历史成功代替当前验证。
- Windows 文件操作使用 PowerShell 原生命令和 LiteralPath；任何递归删除/移动前验证绝对范围。构建及依赖缓存放在 build/，离线验证优先使用本地依赖。
- 现行文档分工：README为入口，docs/user-guide.zh-CN.md维护开发/CLI，architecture.md维护架构，api.md维护契约，delivery.zh-CN.md维护本地打包。历史资料必须标明时点，不能把旧包或旧测试数字当作当前结果。生成日志写入所选构建目录的logs/。
