# Blutter Runner 多版本支持

SOMCP 内置的 Blutter 逆向能力依赖预编译的 `libblutter_<id>.so` Runner。历史上
`runners.json` 内置了多个 Runner（含 Flutter 3.44.x / Dart 3.12.2，以及新增的 Flutter 3.41.x / Dart 3.11.5，均为 arm64-v8a），
且选择逻辑只做「单值引擎修订 + Dart 版本」的精确比对——任何其它 Dart/Flutter
版本都会直接被判为 `FLUTTER_VERSION_NOT_SUPPORTED`。

本文说明新的**分层匹配**机制：一个内置 Runner 现在可以覆盖多个 Dart/Flutter 版本，
以及如何把更多版本纳入支持矩阵。

## 匹配分层（评分从高到低）

`BlutterRunnerMatcher.match()` 对候选 Runner 打分，取最高分者：

| 层级 | 命中条件 | 分数 | 兼容性标记 |
| --- | --- | --- | --- |
| 1 | `requirement.engineRevision` == Runner 的 `engineRevision`（单值） | 4 | `EXACT` |
| 2 | `requirement.engineRevisions` 任一命中 Runner 的 `engineRevisions` 列表 | 3 | `EXACT` |
| 3 | `requirement.dartVersion` == Runner 的 `dartVersion` | 2 | `EXACT` |
| 4 | `requirement.snapshotHash` == Runner 的 `snapshotHash` 或出现在 `snapshotAliases` | 1 | `SNAPSHOT_ALIAS` |

前三级都是 `EXACT`；第 4 级是 `SNAPSHOT_ALIAS`——目标快照格式与 Runner 一致，
但引擎/版本字符串不完全相同，属于同一快照格式下的安全多版本回退。

### 近似兜底（APPROXIMATE）

当 `allowApproximate = true` 且没有上述任何命中时，会选择**同 ABI / 同指针档位 /
同分析开关**的第一个 Runner，并标记为 `APPROXIMATE`。

> ⚠️ 近似匹配只保证二进制格式相近，**不保证语义正确**。恢复出的符号表可能不完整
> 或不准确。`BlutterCoordinator.analyze` 在 `APPROXIMATE` 命中时会在返回结果里附带
> `warnings`，调用方必须如实呈现给用户。

## 数据流

```
FlutterArtifactInspector.inspectLibraries()
    └─ 提取指纹：engineIds[]、dartVersion、snapshotHash、compressedPointers、abi
BlutterCoordinator.analyze()
    └─ 组装 BlutterRunnerRequirement(engineRevision, engineRevisions, dartVersion, snapshotHash, abi, compressedPointers, analysis)
BlutterRunnerRegistry.match(requirement, allowApproximate = true)
    └─ BlutterRunnerMatcher.match()  → RunnerMatch(descriptor, compatibility, score)
BlutterCoordinator.analyze()
    ├─ 命中：embedded.start(jobId, match.descriptor, ...) 并回传 compatibility / warnings
    └─ 未命中：动态回传 supportedRunners 清单（不再硬编码版本号）
```

## 把更多版本纳入支持

代码已支持多版本，但**真正能解析的前提是存在对应 Runner 的 `.so` 二进制**。
扩展矩阵有两种路径：

### 路径 A：同快照格式的已知版本（无需新二进制）

若目标 APK 的 `snapshotHash` 与某个已内置 Runner 相同（或你知道它们在快照格式上兼容），
只需在 `runners.json` 该 Runner 的 `snapshotAliases` 中追加该 hash，即可被第 4 层命中：

```json
{
  "runnerId": "dart-3_12_2-5e4949e6decb093d82c1",
  "snapshotAliases": ["ace654289f5abc240509fc941453ebc5", "<新版本的 snapshotHash>"],
  "snapshotHash": "ace654289f5abc240509fc941453ebc5"
}
```

`snapshotHash` 取自 `FlutterArtifactInspector` 对 `libapp.so` 中
`_kDartVmSnapshotData` 的提取（见 `engineEvidence` / `snapshotEvidence`）。

### 路径 B：全新 Dart/Flutter 版本（需要构建新 Runner）

1. 用 Blutter 工具链按目标 Dart 版本构建 `libblutter_<id>.so`（见仓库 `tools/` 与
   `build-*.ps1` 中的 Runner 矩阵工具链）。
2. 在 `runners.json` 的 `runners` 数组新增一条，至少包含：

   ```json
   {
     "runnerId": "dart-<ver>-<compatKey>",
     "dartVersion": "<x.y.z>",
     "engineRevision": "<40位引擎哈希>",
     "engineRevisions": ["<引擎哈希1>", "<引擎哈希2>", "..."],
     "snapshotHash": "<32位快照哈希>",
     "snapshotAliases": ["<32位快照哈希>"],
     "abi": "arm64-v8a",
     "compressedPointers": true,
     "analysis": true,
     "libraryName": "blutter_<compatKey>",
     "sha256": "<so 的 sha256>",
     "flutterVersions": ["<flutter 版本>", "..."]
   }
   ```
3. 把构建产物放到 `app/src/main/jniLibs/<abi>/` 下，文件名与 `libraryName` 对应。
4. 同步在 `coverage` 数组把对应版本标为 `"supported": true`，便于审计与 UI 展示。

## 兼容性与测试

- `BlutterRunnerMatcherTest` 覆盖：单值引擎修订优先于 Dart 版本、`engineRevisions` 列表匹配、
  `snapshotAliases` 匹配、以及 `allowApproximate` 兜底开关。
- `BlutterRunnerDescriptor` / `BlutterRunnerRequirement` 新增字段均有默认值，
  既有调用方（含测试）无需改动即可编译。
