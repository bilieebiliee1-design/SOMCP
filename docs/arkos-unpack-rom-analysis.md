<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# ArkOS-angler-8.1 脱壳机 ROM 静态分析报告

> 目的：为 `core/IntegrityGuard.kt` 的 ROM 级防脱壳检测提供可复核的证据链。
> 分析对象：`D:\ArkOS-angler-8.1`（`boot.img` / `recovery.img` / `system.img` / `vendor.img`）。
> 方法：**纯静态、离线、只读**。未执行镜像内任何代码，未刷机，未改动原始镜像。
> 结论强度：本文中「实测」= 由镜像字节直接读出；「推断」= 由实测事实推理，已单独标注。

---

## 1. 结论摘要

`ArkOS-angler-8.1` 是一个**免 root、ROM 级**的自动脱壳系统（"脱壳机"）。它不向目标进程注入任何模块，而是**直接改造平台自身**：被脱壳应用的 DEX 由它所运行的 ART 运行时主动写出到 `/sdcard/Ark脱壳机/<进程名>/`。

这与 SOMCP 1.0.22 已覆盖的注入式脱壳（Xposed/LSPosed 模块，如 Layout Inspect）是**不同层**的威胁：

| | 注入式脱壳（已覆盖） | ROM 级脱壳（本次） |
| --- | --- | --- |
| 改造位置 | 目标进程（模块 dex 加载进我们进程） | 平台（`libart.so` / `ActivityThread` / `DexFile`） |
| 进程内痕迹 | 线程栈有 hook 帧、`maps` 有模块库 | **无** —— 我们进程里一切"正常" |
| 应用侧可阻止 | 可检测并拒绝运行 | **无法阻止转储本身**，只能识别环境并拒绝运行 |

三处被改造的平台件（均为 boot classpath，均可由任意应用反射观测）：

1. `lib64/libart.so` — 原生转储实现 `ArkDumpControl`；
2. `android.app.ActivityThread` — Java 侧转储编排（FART 系）；
3. `dalvik.system.DexFile` — 转储开关 `setFartDumpEnabled`。

---

## 2. ROM 身份（实测）

`system.img` 的 `/build.prop`：

```
ro.build.display.id=aosp_angler-userdebug 8.1.0 OPM8.190105.002 eng.ubuntu.20260705.125925 test-keys
ro.build.type=userdebug
ro.build.tags=test-keys
ro.build.version.sdk=27
ro.build.version.release=8.1.0
ro.product.model=Ark脱壳机(菜鸟八哥QQ2380494437)
ro.vendor.product.model=Ark脱壳机(菜鸟八哥QQ2380494437)
ro.product.device=angler
ro.build.fingerprint=Android/aosp_angler/angler:8.1.0/OPM8.190105.002/ubuntu07051259:userdebug/test-keys
```

`ro.product.model` 即 `android.os.Build.MODEL` 的来源，字面包含品牌串 `Ark脱壳机`。

`boot.img` 的 ramdisk（gzip → cpio，2 900 648 B）里 `default.prop` 为 `ro.secure=1` / `ro.debuggable=1`；`init.rc` 是标准 AOSP 内容，**未发现**任何与转储相关的 service / `setprop`。→ 触发面不在 boot 层（实测）。

---

## 3. 三处平台改造

### 3.1 `lib64/libart.so`（7 749 632 B）— 原生转储实现

注入符号（`strings`，实测）：

```
_ZN3art17IsFartDumpEnabledEv                          art::IsFartDumpEnabled()
_ZN3art18SetFartDumpEnabledEb                         art::SetFartDumpEnabled(bool)
_ZN3art21DumpFartDexFileDirectEPKNS_7DexFileEPKc      art::DumpFartDexFileDirect(art::DexFile const*, char const*)
_ZN3art12_GLOBAL__N_119g_fart_dump_enabledE           g_fart_dump_enabled
_ZN3art12_GLOBAL__N_121g_fart_next_dex_indexE         g_fart_next_dex_index
_ZN3art12_GLOBAL__N_123g_fart_dumped_dex_filesE       g_fart_dumped_dex_files
_ZN3artL26DexFile_setFartDumpEnabledEP7_JNIEnvP7_jclassh
```

日志与路径（实测，UTF-8 还原）：

```
ArkDumpControl: SetArkDumpEnabled=
ArkDumpControl: DumpFartDexFileDirect 收到空 DexFile
ArkDumpControl: 无法获取当前进程名
ArkDumpControl: 创建 DEX 文件失败
ArkDumpControl: DEX 导出成功
ArkDumpControl: 无法打开
ArkDumpControl: 创建目录失败
/sdcard/Ark脱壳机
classes.dex
classes%zu
persist.sys.fart.allow_dex_039_040
FartDumpControl: 允许实验性加载 DEX
ArkDumpControl: 强制允许加载 DEX
ArkDumpControl: DEX 加载开关已关闭
```

→ 输出布局为 `/sdcard/Ark脱壳机/<进程名>/classes.dex`，多 dex 追加 `classes%zu.dex`。与 ROM 的 `README.txt` 所述「脱壳文件默认输出目录：/sdcard/Ark脱壳机/<进程名>/」一致。

32 位 `/lib/libart.so`（5 886 640 B）含同族内容（`/sdcard/Ark脱壳机`、`ArkDumpControl`、`FartDumpControl`、`/runtime/native_bridge_art_interface.cc`）。

> 「FART」是该方案的家族名（ART 环境下的主动调用式脱壳框架）；作者在此基础上做了品牌化改造（`ArkDumpControl`）与日志中文化。**推断**：`libartd.so`（调试版，7 019 024 B / 5 116 712 B）同样被改造 —— 实测其含完全相同的字符串，但 debug 版通常不参与实际启动。

### 3.2 `android.app.ActivityThread` — Java 侧转储编排

由 `/framework/arm64/boot-framework.vdex`（vdex v010，2 个内嵌 dex，60 83 + 51 54 个类）解析 `Landroid/app/ActivityThread;` 的类数据（实测；`acc` 为 DEX access_flags）：

| 方法 | acc | 说明 |
| --- | --- | --- |
| `readFartDumpSwitches` | 0x0002 | 读转储开关 |
| `startFartDumpThreadIfNeeded` | 0x0002 | 起转储线程 |
| `runFartDump` | 0x0002 | 主流程 |
| `getFartProcessDirectory` | 0x0002 | 进程输出目录 |
| `getFartDumpDelaySeconds` | 0x0002 | 延迟 |
| `dumpDexClasses` | 0x0002 | 遍历 DexFile cookie |
| `dumpDexFromClassLoader` | 0x0002 | 按 ClassLoader 转储 |
| `dumpDexFromElement` | 0x0002 | 按 DexPathList element 转储 |
| `dumpSingleDexFile` | 0x0002 | 单文件写出 |
| `isDumpDexFilesEnabled` | 0x0002 | 开关判定 |
| `isDumpArtInstructionsEnabled` | 0x0002 | ART 指令转储开关 |
| `isDumpTrapClass` | 0x0002 | 类过滤 |
| `parseDumpExcludedClassRules` | 0x0002 | 排除规则 |
| `writeFartApkAndManifest` | 0x0002 | 落 APK + manifest |
| `writeFartApplicationInfo` | 0x0002 | 落 applicationInfo |
| `copyFartFile` | 0x0002 | |
| `extractFartZipEntry` | 0x0002 | |
| `sanitizeFartFileName` | 0x0002 | |
| `clearFartProcessDirectory` | 0x0002 | |
| `deleteFartFileRecursively` | 0x0002 | |
| `showFartDumpCompletedToast` | 0x0002 | 完成提示 |

**同一类中的 stock 方法（对照，AOSP `am dump` 用，不应作为判据）**：`handleDumpActivity`、`handleDumpProvider`、`handleDumpService`、`handleDumpHeap`、`handleStopBinderTrackingAndDump`、`dumpMemInfoTable`、`nDumpGraphicsInfo`。

配套字符串（实测）：类名 `FartDumpControl`；日志标签 `Ark DumpControl`；键 `getFartDump{Art,Dex}EnabledKey`、`getFartDumpDelaySeconds{,Key}`、`getFartDumpExcludedClassesKey`；字段 `mFartDumpDelaySeconds`、`mFartDumpThreadStarted`、`mFartRealApplicationName`、`mFartShellApplicationName`；配置键 `fart_dump_art_enabled_`、`fart_dump_dex_enabled_`、`fart_dump_delay_seconds_`、`fart_dump_excluded_classes_`、`persist.sys.fart.auto_storage_permission`、`persist.sys.fart.verify_app_signature`；常量 `DEFAULT_FART_DUMP_DELAY_SECONDS`、`MAX_FART_DUMP_DELAY_SECONDS`；中文日志 `FART 延迟时间为 0，立即执行`、`FART 根路径不是目录：`、`FART 线程等待应用初始化：`、`FART 进程路径不是目录：`。

### 3.3 `dalvik.system.DexFile` — 转储开关

由 `/framework/arm64/boot-core-libart.vdex` 解析 `Ldalvik/system/DexFile;` 的直接方法（实测）：

```
closeDexFile                 acc=0x010a code=0x0   <== NATIVE
dumpDexFile                  acc=0x0109 code=0x0   <== NATIVE   （非 stock，但本次未作判据，见 §5）
getDexFileOutputPaths        acc=0x0109 code=0x0   <== NATIVE
getDexFileStatus             acc=0x0109 code=0x0   <== NATIVE
getDexOptNeeded              acc=0x0109 code=0x0   <== NATIVE
isDexOptNeeded               acc=0x0109 code=0x0   <== NATIVE
loadDex                      acc=0x0009 code=0x190aac
loadDex                      acc=0x0008 code=0x190ac8
openDexFile                  acc=0x000a code=0x190af0
openDexFileNative            acc=0x010a code=0x0   <== NATIVE
openInMemoryDexFile          acc=0x000a code=0x190b38
setFartDumpEnabled           acc=0x0109 code=0x0   <== NATIVE   ← 注入
```

`acc=0x0109` = `ACC_PUBLIC | ACC_STATIC | ACC_NATIVE`，`code=0x0` = 无代码项（native）。
`lib64/libart.so` 内的 `RegisterNatives` 签名表提供交叉印证：`setFartDumpEnabled.(Z)V`、`dumpDexFile.(Ljava/lang/Object;)V`。

---

## 4. 转储流程（实测 + 推断）

```
ActivityThread.readFartDumpSwitches()          ← 读 fart_dump_dex_enabled_* / persist.sys.fart.*
        │
        ▼
ActivityThread.startFartDumpThreadIfNeeded()   ← 按 fart_dump_delay_seconds_* 延迟，等待应用初始化
        │
        ▼
ActivityThread.runFartDump()
        ├── dumpDexClasses / dumpDexFromClassLoader / dumpDexFromElement
        │        └── 遍历 BaseDexClassLoader 的 DexFile cookie（即内存中的已解密 DEX）
        │                └── DexFile.setFartDumpEnabled(true)   ← 打开原生开关
        │                        └── art::DumpFartDexFileDirect(DexFile const*, char const*)
        │                                └── 写出 /sdcard/Ark脱壳机/<进程名>/classes.dex（多 dex 为 classes%zu.dex）
        ├── writeFartApkAndManifest / writeFartApplicationInfo   ← 同时落 APK 与 manifest
        └── showFartDumpCompletedToast()
```

**推断**（未实测的部分）：转储线程在目标应用进程内启动，因此 `persist.sys.fart.*` 与 `fart_dump_*` 是跨进程生效的全局开关；具体由哪个 UI 入口写入这些开关（本 ROM 未发现专用脱壳 App，`/app/AnglerLayout` 经查为 Launcher3 的伙伴定制包 `com.google.android.launcher.layouts.angler`，与转储无关）**本次未定位**。这不影响检测设计：检测点选在"平台声明面"，与开关状态无关。

---

## 5. 检测设计

### 5.1 判据（`IntegrityGuard.fartDumpThreat`）

| 观测 | 判据 | 依据 |
| --- | --- | --- |
| `dalvik.system.DexFile` 的声明方法名 | 含 `setFartDumpEnabled` | §3.3 实测；stock 不声明 |
| `android.app.ActivityThread` 的声明方法名 | 含 `runFartDump` / `startFartDumpThreadIfNeeded` / `readFartDumpSwitches` / `getFartProcessDirectory` 之一 | §3.2 实测；均带 FART 品牌，stock 不可能命中 |

两者都在 boot classpath → 任意应用**无需权限、不 hook、不读文件**即可反射观测。任一命中即判威胁。

### 5.2 判据取舍（为什么少报而不是多报）

- **`dumpDexFile` 不用。** 它与 `setFartDumpEnabled` 同为 `public static native` 且相邻，但本次**无法离线取得 stock 8.1 的 `core-libart` 做对照**，不能确证其非 stock。按「无法验证就不作判据」处理。测试 `stockDumpSurfaceAndEmptyEvidenceAreNotThreats` 把它钉在"不触发"一侧。
- **`/system/fake-libs{,64}/libart.so` 不用。** 该 stub 导出 `art::Dbg::SuspendVM` / `ResumeVM` / `art::FaultManager::EnsureArtActionInFrontOfSignalChain` 并含 `libart_fake` 串与 "Linking to and calling into libart.so internal functions is not supported"。对 `system.img` 全盘（3.22 GB 逻辑空间）字节检索 `fake-libs` 仅 6 处命中：`boot-framework.{art,vdex}` × 2 ABI 的路径表 + ext4 根目录项，**未**被 `/bin/linker{,64}`、`/etc/ld.config.txt` 或任何 init 脚本引用 → 与 stock AOSP 的 `libart_fake` 安装位一致，判定为非判别性。
- **`/etc/ld.config.txt` 被换成 pre-O 非隔离 legacy 配置**（486 B，`namespace.default.isolated = false`，全局单一命名空间）—— 实测事实，但它是"削弱命名空间隔离"，不是转储本身，故不作判据。
- **`persist.sys.fart.allow_dex_039_040` 不用。** 读取它需要反射进隐藏的 `android.os.SystemProperties`；两个类级判据在证据强度上严格更强（证明补丁存在，而非仅证明某个开关被设置）。
- **匹配用精确成员名。** `setFartDumpEnabledX` / `xsetFartDumpEnabled` / `runFartDumpNow` 均不命中。
- **空证据不报。** 反射失败（`Class.forName` 抛错）退化为空列表 = 无证据，不 fail-closed —— 与 `hookFrameThreat` 语义一致：缺失证据不等于存在威胁。

### 5.3 旁路：ROM 身份（`arkUnpackRomThreat`）

`Build.MODEL` / `Build.DISPLAY` / `Build.FINGERPRINT` 任一包含 `Ark脱壳机` 即判威胁。单独看弱于 §5.1（能刷 ROM 的人也能改 `build.prop`），但成本是三次字符串比较，且在被改类名时仍能命中。此处用**子串**匹配（作者固定品牌，版本后缀或 QQ 号变更不应关掉检查）——这与 `foreignFactoryThreat` 的精确匹配不同，因为那里的值由攻击者选定，精确匹配才不被近似串绕过。

### 5.4 能力边界（必须如实说明）

转储由**拥有我们 DEX 的 ART 运行时**执行。应用侧**没有任何手段阻止转储本身**：DEX 在内存中是明文，写出动作发生在我们无权干预的原生层。因此本检测的语义是「识别环境并 fail-closed 拒绝运行」，不是「保护 DEX 不被写出」。这与注入式脱壳（可以检测并拒绝）在强度上有本质差别。

---

## 6. 方法与可复现性

因 `system.img` 是 1.0 GB Android sparse 镜像、解包后为 3.22 GB ext4，而本机 C 盘余 289 MB / D 盘余 2.4 GB，**无法落地整盘**；7-Zip 26.02 能打开内层 ext4 但目录列举为空。故本次自建只读工具链，全部流式、不物化镜像：

- sparse 解码器 + 最小 ext4 读取器（superblock / 组描述符 / extent 树 / 目录项 / inode）；
- 全逻辑空间字节检索并按 inode extent 归属到具体文件（3.22 GB 约 5 s）；
- vdex（v010）→ 内嵌 DEX 解析（string_ids / type_ids / method_ids / class_defs / class_data_item）；
- boot.img 解析 + cpio newc 解包。

校验点：ext4 卷标 `system` / `vendor`；`system.img` 2731 个条目、`vendor.img` 874 个；vdex 魔数 `vdex010`，内嵌 dex 魔数 `dex\n038`。

---

## 7. 未验证项

1. **真机回归未执行。** 未在 Nexus 6P + 该 ROM 上安装 SOMCP 验证检测实际触发。
2. **本地构建 / ktlint / 单测未执行**（本机无 Kotlin 编译器、无 `~/.gradle` 缓存、`D:\Gradle` 仅剩 wrapper，磁盘不足）。随 CI 补验。
3. **stock 8.1 `core-libart` 对照缺失**，故 `dumpDexFile` 未纳入判据（见 §5.2）。
4. **触发开关的写入方未定位**（§4）。
5. **`vendor.img` 未发现相关改造**（874 条目已全部列举，无 Ark/FART 痕迹）。

---

## 8. 附录：关键原始证据索引

| 证据 | 位置 |
| --- | --- |
| `ArkDumpControl` / `/sdcard/Ark脱壳机` / `classes%zu` | `/lib64/libart.so` file_off `0x54fa83` 附近；`/lib/libart.so` `0x446e30` |
| `IsFartDumpEnabled` / `SetFartDumpEnabled` / `DumpFartDexFileDirect` | `/lib64/libart.so` dynsym |
| `setFartDumpEnabled.(Z)V`（RegisterNatives） | `/lib64/libart.so` file_off `0x57551f` |
| `persist.sys.fart.allow_dex_039_040` | `/lib64/libart.so` file_off `0x55a807` |
| `FartDumpControl` / `Ark DumpControl` | `/framework/arm64/boot-framework.{art,vdex}` |
| `runFartDump` 等 20+ 方法 | `Landroid/app/ActivityThread;` @ `/framework/arm64/boot-framework.vdex` |
| `setFartDumpEnabled` / `dumpDexFile`（native） | `Ldalvik/system/DexFile;` @ `/framework/arm64/boot-core-libart.vdex` |
| ROM 身份串 | `/build.prop` |
| `/system/fake-libs{,64}/libart.so`（非判别性） | `/fake-libs{,64}/libart.so` |

---

**法律与用途**：本文仅对用户本地提供的镜像做静态只读检查，不执行样本、不用于绕过他人软件的保护措施。请仅对自己拥有或已获授权的镜像与软件进行分析。
