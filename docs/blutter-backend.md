# Blutter 全本地后端

## 目标

SOMCP 在单个 APK 内提供 Flutter Android AOT 分析。当前正式发行版只内置 Flutter 3.44.2–3.44.7 / Dart 3.12.2 arm64 compressed-pointer analysis Runner。运行时不依赖 Python、Git、CMake、Termux、独立 Runner APK 或远端服务，不上传 `libapp.so`、`libflutter.so`、符号、对象池或分析结果。

构建机从官方 Flutter archive 解析 stable 版本，固定 Blutter commit，并为发行矩阵选定的兼容键下载对应 Dart SDK 源码、交叉编译 Android arm64 Runner。历史索引只用于识别和构建规划，不代表全部打包。Android 设备冒烟是可选增强验证，不是用户安装或应用运行前置条件。

## 支持边界

- 正式分析目标为 Android `arm64-v8a` Flutter AOT。
- 输入必须提供同一 ABI 的 `libapp.so` 与 `libflutter.so`。
- runner 兼容键包含 engine revision、Dart revision/version、snapshot hash、compressed pointers、analysis mode 与 Blutter commit。
- Dart `<2.15` 只允许 no-analysis；不能声明完整对象、类和函数分析。
- 修改过 engine、无法解析 revision、静态构建失败或冒烟明确失败的版本返回明确的不支持原因。
- “历史版本已索引”不等于“历史版本已支持”。发布清单只声明实测通过项。

## 运行架构

```text
MCP flutter_blutter
        |
BlutterCoordinator
        |-- FlutterArtifactInspector
        |-- BlutterRunnerRegistry
        |-- BlutterResultStore
        `-- BlutterEmbeddedBackend
                 |
                 | AIDL + ParcelFileDescriptor
                 v
          :blutter isolated process
                 |
          libblutter_bridge.so
                 |
          libblutter_<compatibility-key>.so
```

主进程只提取、指纹识别、runner 选择、结果校验与提交。隔离进程只接触三个 descriptor：`libapp.so`、`libflutter.so` 和输出文件。版本 runner 只从 APK 的只读 native library 目录加载，不从可写目录执行代码。

隔离进程内运行一个**有界线程池**（默认 `min(CPU 核数, 8)`，至少 2），因此多个反汇编作业可以**并发**执行。并发安全由两个约束保证：

- **按 runner 库串行**：目标为**同一个 runner 库**的作业通过「按库加锁」（`BlutterRunnerService.libraryLocks`，对同一个 monitor 对象 `synchronized`）串行执行，因为底层 Dart VM runner 持有进程级全局状态、不可重入。这一步直接兜住同进程内 Dart VM 全局状态冲突——同一个库绝不会在进程内被并发驱动。
- **不同库真正并行**：原生侧以 `RTLD_LOCAL` 加载（见 `cpp/blutter_bridge.cpp`），每个 `nativeRun` 调用独立 `dlopen`→`dlsym`→`dlclose`，符号对各自 handle 私有，不同 runner 库的作业在各自线程里真正并行、互不影响。

「同进程内同一个库的多 runner 并发」保持关闭（按库锁串行），直到 Dart VM 全局状态压测通过；若未来要放开，再去掉按库锁、让同库也并行即可。线程池大小有上限，单个作业的墙钟超时仍由进程内看门狗强制（取消 → 宽限 5 秒 → `RUNNER_TIMEOUT` → `stopSelf()` 拆除整个进程）。进程在有活跃作业时保活，全部作业结束 30 秒后才退出，省去每次作业重建进程的开销。

## Runner 清单

`app/src/main/assets/blutter/runners.json` 是 APK 能力的唯一事实来源：

```json
{
  "schemaVersion": 2,
  "matrixVersion": "2026.07.1",
  "protocolVersion": 1,
  "upstreamCommit": "528acbe83ba35a3a53fb97b231cb5f968c7068d1",
  "generatedAt": "2026-07-23T00:00:00Z",
  "runners": [],
  "coverage": []
}
```

`runners` 只包含可执行条目。每项必须包含唯一 `runnerId`、`libraryName`、ABI、Dart version/revision、engine revision、snapshot aliases、指针模式、分析能力、SHA-256、构建状态、静态验证状态和冒烟状态。`smokeStatus` 可以是 `not_run` 或 `passed`；只有 `failed` 才禁止入包。

`coverage` 包含全部索引版本及状态，用于解释未覆盖原因。状态流为：

```text
indexed
  -> source_resolvable
  -> dartvm_built
  -> blutter_built
  -> android_built
  -> static_verified
  -> smoke_passed (optional)
  -> supported
```

失败原因固定为 `source_unavailable`、`dartvm_compile_error`、`blutter_compile_error`、`android_cross_compile_error`、`android_icu_unavailable`、`android_capstone_unavailable`、`runner_crash`、`snapshot_mismatch`、`modified_engine` 或 `smoke_output_invalid`。未连接设备时不产生失败，只保留 `smokeStatus=not_run`。

## 构建矩阵

`tools/blutter-matrix` 负责构建期编排：

1. 下载并校验官方 Flutter release archive JSON。
2. 从 framework revision 解析 `bin/internal/engine.version`。
3. 从 engine revision 解析 Dart SDK revision 与版本。
4. 按 Dart revision、compressed pointers、analysis mode 和 Blutter commit 去重。
5. 下载固定 revision 的 Dart SDK/engine 源码。
6. 使用固定 Android NDK 交叉编译 `arm64-v8a` 共享库。
7. 校验导出符号、依赖闭包、SHA-256 和结构化结果静态契约后生成 APK 清单。
8. 可选地在 Android 设备或模拟器运行已知 Flutter fixture 冒烟，并回填清单状态。

构建期脚本可以使用 Python；Python 不进入 APK，也不参与手机端分析。

## 作业协议

作业 ID 使用 `blutter-<UUID>`。状态机为：

```text
queued
  -> resolving_input
  -> fingerprinting
  -> selecting_runner
  -> running
  -> normalizing
  -> committing
  -> succeeded

任意运行阶段 -> cancelling -> cancelled
任意运行阶段 -> failed
进程终止后的非终态作业 -> interrupted
```

`status` 与 `stage` 之外，运行中作业的状态还会写入 `progressPercent`（0–100）与 `progressEstimated`（布尔）。进度是**诚实值、不做时间假推进**：作业开始时标记 `disassembling` 且 `progressPercent=0`；若原生 runner 回传子阶段进度则原样转发（标记 `progressEstimated=false`）；`committing` 阶段由编排层写入确定性的 `100%`（`progressEstimated=false`）。我们不靠计时器把百分比向 90% 线性伪造。`status` 查询会原样返回这些字段。

结果缓存键为：

```text
SHA-256(
  libappSha256 + libflutterSha256 + runnerSha256 +
  normalizerVersion + canonicalOptionsJson
)
```

结果先写入唯一 staging 文件并校验 schema、大小、artifact 相对路径和摘要，再原子替换不可变结果文件。成功状态统一为 `succeeded`。分页游标绑定 job、实体类别和偏移，不能跨作业或跨类别复用。

## 更新策略

应用设置提供三个更新通道：

- `stable`：只提示正式 GitHub Release，默认选项。
- `beta`：允许包含新 runner 覆盖但尚未作为稳定版本发布的预发布 APK。
- `manual`：不自动检查，只在用户触发时查询。

更新页面展示应用版本、matrix version、新增 runner 数、修复 runner 数、`unsupported -> supported` 数和撤销 runner 数。由于 runner 是 APK 原生代码，更新必须通过完整 APK 安装完成，不能动态下载 `.so` 到数据目录执行。

## 安全边界

- APK 最大 512 MiB，单 SO 最大 256 MiB，并限制 ZIP 条目数、累计解压量和压缩比。
- 只提取精确的 `lib/<abi>/libapp.so` 与 `lib/<abi>/libflutter.so`。
- 拒绝绝对路径、`..`、NUL、重复目标和越界 artifact。
- runner library name 只允许 `blutter_[A-Za-z0-9_]+`，并且必须存在于已校验清单。
- 不执行目标 APK 中任何代码，不加载用户提供的 SO，不调用下载到可写目录的二进制。
- 每个作业限制输入、输出、文件数、内存和墙钟时间。**墙钟超时现已强制**：`analyze` 可传 `timeoutMillis`（默认 30 分钟，夹在 1–60 分钟之间）。主进程编排层与隔离进程内各自持有一个看门狗——编排层覆盖「服务从未连上」的场景并产出结构化 `RUNNER_TIMEOUT`；隔离进程内的看门狗在超时后先请求取消、再给 5 秒宽限，仍未结束则上报 `RUNNER_TIMEOUT` 并 `stopSelf()` 拆掉整个隔离进程，确保单个卡死的作业永远不会把 runner 挂死。
- 日志不记录符号全文、对象池内容或输入私有路径。

## MCP 操作

- `inspect`：识别 Flutter 输入和兼容指纹。
- `analyze`：选择同 APK runner 并创建本地作业。可选参数 `timeoutMillis`（墙钟超时，毫秒，默认 30 分钟、夹在 1–60 分钟）控制隔离进程行为。
- `status`：查询阶段、进度和结构化错误。
- `result`：读取结构化结果和分页实体。
- `cancel`：取消运行作业并终止隔离进程。
- `packages`：返回 All-in-One APK 的 runner 与历史覆盖状态。
- `prune`：清理未被成功作业引用的旧缓存。

`backend` 仅接受 `auto` 或 `embedded`，两者都只执行 APK 内置 runner。

## 验收门槛

- 飞行模式下完成识别、分析、分页查询和缓存复用。
- APK 中每个 runner 的 SHA-256 与清单一致，并导出 `blutter_run_fd`。
- 每个 `supported` 条目都有构建和静态验证记录；Android 冒烟记录可选，明确失败的条目不得进入 APK。
- 缺失 runner 返回 `VERSION_UNSUPPORTED` 和覆盖原因，不建议安装独立包或启用远端。
- runner 崩溃、超时、取消、输出超限和 Binder 死亡产生结构化终态。
- 单次作业结束后隔离进程退出，下次作业使用新进程。
- `result.json` 与分页响应通过 schema 校验，地址始终使用十六进制字符串。
