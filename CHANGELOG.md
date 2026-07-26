# 更新日志

## 1.0.9

本节记录基于 `1.0.8` 的未发布变化。

- 增强 Blutter Runner 多版本支持：匹配改为分层选择，单个内置 Runner 即可服务多个 Dart/Flutter 版本——依次按「引擎修订单值 → 引擎修订列表(`engineRevisions`) → Dart 版本 → snapshot hash 别名(`snapshotAliases`)」评分，并支持同 ABI/指针档位下的近似兜底(`APPROXIMATE`，结果带明确警告)。`BlutterRunnerRequirement` 现携带完整 `engineIds` 与 `snapshotHash`；`runners.json` 的 runner 也解析并暴露 `engineRevisions`/`snapshotHash`；匹配失败时不再硬编码"仅 3.44.x / 3.12.2"，而是动态回传内置 `supportedRunners` 清单。详见 `docs/blutter-multi-version.md`。
- 新增 Dart 3.11.5 解析支持（对应 Flutter 3.41.7 / 3.41.8 / 3.41.9，snapshotHash `78da37fed6bf1489361a312568249f3f`）：将 `3.11.5` 加入 `tools/blutter-matrix/curated-versions.json` 的 `dartVersions`，由 Runner 矩阵流水线构建对应 `libblutter_<compatKey>.so`（arm64-v8a，compressedPointers + analysis）并改写 `runners.json` 使其 `supported=true`。注意：本仓库当前仅声明了构建意图，未内置该 Runner 的预编译产物；需在具备 NDK 29 / ICU 76.1 / capstone 4.0.2 且可访问 GitHub / Flutter 分发源的环境中运行 `tools/blutter-matrix/` 流水线，再把生成的 `.so` 与 `runners.json` 一并提交，功能方可实际使用。
- 新增统一「备份与恢复」入口：设置页新增「备份与恢复」，可本地导出 / 导入整份配置快照（JSON）。密钥默认脱敏，仅勾选「包含密钥」后写入真实 token/key；导入时仅在备份本身含密钥且用户允许时才恢复密钥，避免脱敏占位符覆盖真实值。
- 新增可选远程备份：支持 WebDAV（Basic Auth）与 S3 兼容存储（AWS Signature V4、路径式寻址，含 MinIO 等自建对象存储）。上传以带时间戳文件名保存，恢复时按文件名拉取。远程凭据仅保存在本机，不进入备份文件。
- 新增 `BackupManager` 与 `BackupPrefs`：复用既有 `SettingsStore.snapshot/applyPatch` 快照能力并封装带版本信封；远程目标配置独立存放于同一 `so_reverse_mcp` SharedPreferences，与快照数据解耦。
- 优化 Blutter 反汇编的可观测性与并发（多线程并行）：
  - **多线程 + 按库串行**：`BlutterRunnerService` 由单线程改为有界线程池（默认 `min(CPU 核数, 8)`，至少 2），多个反汇编作业可**并发**执行。并发安全由两个约束保证：① 按 runner 库（`libraryName`）加锁串行，同一个库永不在进程内被并发驱动，从根上兜住 Dart VM 进程级全局状态重入；② 不同库各自 `dlopen`(`RTLD_LOCAL`)、符号对各自 handle 私有，在各自线程里真正并行、互不影响。
  - **进程保活 + 空闲停机**：隔离进程在有活跃作业时保活（通过 `startService` 自提升为 started service，避免被系统回收），全部作业结束后 30 秒才退出，省去每次作业重建进程的开销；空闲停机前会把新提交的作业计入活跃计数，避免被误杀。
  - **墙钟超时（双层看门狗）**：`analyze` 可传 `timeoutMillis`（默认 30 分钟、夹在 1–60 分钟）由编排层与隔离进程各自强制。编排层拆成「连接看门狗（短，覆盖服务从未连上）」+「作业看门狗（连接后才启动，避免排队作业被误超时）」；隔离进程内超时先请求取消、宽限 5 秒仍未结束则上报结构化 `RUNNER_TIMEOUT` 并 `stopSelf()` 拆除整个隔离进程，杜绝卡死作业挂起 runner。（注：硬超时拆除的是共享进程，同进程的其它在跑作业也会一并终止，由编排层经 `onServiceDisconnected` 失败/重提交兜底。）
  - **诚实进度（不做时间假推进）**：状态机保留 `progressPercent` / `progressEstimated`；作业开始标记 `disassembling=0%`，原生回传的子阶段进度原样转发，提交阶段写入确定性的 `100%`。不再用计时器把百分比向 90% 伪造。
  - **同库多 runner 并发暂缓**：虽然按库锁已保证同库永不同步，但同进程内同一个库未来若要放开并发，仍需先经过 Dart VM 全局状态压测；届时直接去掉按库锁即可，不用改其它路径。

## 1.0.8

本节仅记录 `1.0.7` 发布后到 `1.0.8` 发布之间的变化。

- 新增完全离线 Flutter Android AOT 分析链路，内置 Flutter 3.44.2–3.44.7 / Dart 3.12.2 arm64 Blutter Runner，并通过 isolated process、AIDL 与文件描述符隔离执行。
- 新增 `flutter_blutter` 聚合工具、Runner 清单、Flutter APK 指纹识别、作业状态、分页结果、取消和结果持久化能力；非内置 Flutter/Dart 版本返回明确不支持信息。
- 新增设置页 Blutter 配置说明，明确内置版本、离线边界和精确兼容性规则。
- 修复不同设备和窄屏下底部导航最右侧设置按钮被挤压变形的问题。
- 修复更新下载取消后状态未复位、已下载 APK 重进页面无法继续安装、测速结果只显示部分节点的问题。
- 改进 Cloudflare Tunnel URL 历史，支持关闭记录、删除单项和清空全部记录，并优化窄屏端口设置显示。
- 改进访问控制页面，明确本机、局域网和公网隧道三种连接方式；绑定局域网地址时自动启用访问 Token。
- 改进编辑审计设置，增加可勾选的禁用工具选择器，并将模拟执行说明移到对应开关附近。
- 强化 Runner 矩阵工具链，增加官方 snapshot hash 提取、断点续跑、原子状态、产物摘要验证、陈旧 Runner 清理和 NDK 去符号处理。

## 1.0.7

本节仅记录 `1.0.6` 发布后到 `1.0.7` 发布之间的变化。

- 审查并合并 PR #3，明确 SO/ELF 工作流使用内置工具，`mt_apk_*` 仅用于 APK 层操作。
- 拆分主界面、设置页、分析页、工具目录展示、引擎运行时和 MCP 批处理职责，降低超大单文件与跨领域耦合。
- 将 `NativeSoEngine` 收敛为兼容 facade，并按来源、读取、编辑、构建、报告、Rizin、LIEF、Unidbg 和 xAnSo 领域组织实现。
- 将 APK ZIP、DEX 和 Manifest 分析提取为纯 JVM 组件，并增加输入大小、ZIP 条目数、单条目和累计解压上限。
- 修复标准 DEX magic 误判、ASM/符号批量编辑部分提交、LIEF 修改失败仍创建成功会话等问题。
- 为 LIEF JNI 入口增加统一 C++ 异常屏障和空参数检查，避免异常跨越 JNI 导致进程终止。
- MCP `initialize` 现在报告真实构建版本，并集中维护 SO/APK 工具路由指南。
- 增加 APK 分析、批处理模板、JSONPath、事务回滚、工具注册、请求字段及引擎纯逻辑回归测试。
