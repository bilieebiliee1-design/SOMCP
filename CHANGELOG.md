<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# 更新日志

## 1.0.22
- 修改版本为1.0.22，版本号为23
- 降低静态分析的字符串抽取开销（`LiefEngine`，两处，1 个文件 +84/−52）：字符串抽取此前按节把数据整段 `copyOfRange` 出来再扫，`.rodata` / `.data` 单节可达数十 MiB，每进行一次解析都要复制一遍；现改为在原数组上用 `[from, to)` 窗口就地扫描，越界节的地址基准与跳过条件与旧实现逐条对齐。
- 字符串去重集合由 `"UTF-8:<偏移>:<文本>"` 字符串键改为把（偏移、字节长度、编码）打包进一个 `long`。旧键等于给每一条抽出的字符串再保留一份完整文本副本，且在整个扫描期间一直被引用——加固 SO 的整文件扫描下，这份副本与字符串列表本身同量级。新旧键语义等价：偏移与长度都是 `ByteArray` 下标（各 31 位），编码占 1 位，同址同长必然同文本。
- 字符串抽取改为按需触发：`elf.strings` 现在在首次读取时才计算。此前每次 `lief.parse` 都会执行「所有含字符串的节 + 整个文件」的全量扫描，而多处调用方根本不读 `strings`——`prepareAnalysisInput` 中只用于判断节表是否存活的探测解析、工作目录扫描的元数据兜底解析（只取架构/位数）、以及只做符号比对或变更校验的补丁 / 构建前后解析。丢失节表的加固 SO 上，探测解析会把一次整文件扫描的结果直接丢弃，是这条路径上最大的一笔浪费。读取 `strings` 的调用方行为不变（列表内容、顺序、字段与改动前一致），且打开/概览响应仍会在打开时读取它，因此「先解析、再原地改写数据」的既有顺序不受影响。
- 验证方式（不涉及本地构建）：改动文件过 ktlint 1.8.0 零违规（运行前已用探针确认该工具确实会报错，避免「静默通过」）；行宽按**字符数**复核，最长新增行 159 字符（上限 160）。窗口扫描与原 `copyOfRange` 的边界语义逐条核对：越界节（`offset < 0` / `offset > 文件大小`）产出为空、地址基准仍取未钳制的 `sec.offset`，与旧实现一致；`size` 超过 31 位时旧实现会抛异常并触发 `ElfParser` 回退，新实现按空范围跳过（保留 LIEF 的解析结果，不降级）。
- Release 工作流新增 Dex2C 加固步骤（`Harden release APKs with Dex2C (dcc)`，`release.yml`）：每个 release APK 在「Verify and ensure v2/v3 APK signing」之前过一遍 dcc，`tools/dex2c/filter.txt` 选中的方法被翻译成 C、编译进 `lib/<abi>/libnc.so`，dex 中对应方法改为 `native`，原逻辑不再出现在发布包里。工具链全部钉死：dcc 用固定提交 `17de4fd`（master 会移动）、apktool 固定 2.12.1（保留 dcc 编写时所依赖的 2.x CLI，且本仓库的 dex 是 038，用不上 3.x 的 smali）、NDK 复用工作流里已安装的 29.0.14206865。
- `APP_ABI` 与 `APP_PLATFORM` 从 APK 自身推导，而不是沿用 dcc 的模板：dcc 要求 APK 中**每一个** `lib/<abi>/` 目录都存在 libnc.so（`copy_compiled_libs` 缺一个就抛 `ABI x is not supported`），而它 2019 年的 `Application.mk` 只编 android-19 + arm64-v8a/armeabi-v7a，android-19 在 NDK 29 上已不受支持。四个 ABI 分包各自只编自己那一个 ABI，universal 包编四个。
- 加固后必须重签，否则会发出 testkey 包：apktool 重建 APK 时 gradle 的签名已失效，而 dcc 固定用它自带的 testkey 签名。步骤内以 `zipalign -f -p 4` + `apksigner sign`（v1–v4）用 release 密钥重签，并覆盖回 `app/build/outputs/apk/release/`，因此下游的签名校验、重命名、SHA256SUMS 与上传拿到的都是加固后的产物；testkey 包既无法覆盖安装，也会撞上应用自身的签名 pin。
- 加固失败一律让 release 失败，不接受「静默发出未加固包」：过滤规则一条都没命中时 dcc 不产出 APK（它只打印 `no compiled methods` 直接返回），此时以及 `compiled_methods.txt` 中找不到目标类时，步骤以退出码 1 终止。
- 本次加固范围只有 `com.soreverse.mcp.core.BackupCrypto` 一个类。选它是因为 `proguard-rules.pro` 已完整保留该类的原名与成员名，过滤规则可稳定命中 R8 之后的发布 dex、无需依赖 `mapping.txt`；且它是自包含的加密逻辑（Argon2id 参数、AES-256-GCM 数据格式），转换后这些信息不再留在字节码里。
- 配套改动：`BackupCrypto` 新增 `<clinit>` 中的 `runCatching { System.loadLibrary("nc") }`。转换后的方法在调用前必须先加载 libnc.so，而 `<clinit>` 被过滤规则排除、自身不会被转换；未加固的构建（debug、本地 release）没有这个库，加载失败被吞掉，Java 实现照常生效。
- 验证方式（不涉及本地构建）：以 1.0.21 的 arm64-v8a release APK 为探针，确认包里只有 `classes.dex`（7.2 MB、dex 版本 038）、`Lcom/soreverse/mcp/core/BackupCrypto;` 及其成员名在 R8 之后仍是原名；再用钉死的 dcc 提交与本仓库的过滤文件对该真实 dex 跑前端（`--no-build`，不编译任何原生代码），`compiled_methods.txt` 命中 10/10 个方法（构造器与 `<clinit>` 按预期排除），C 源逐个生成。dcc 的依赖在 Python 3.13 下可正常安装、import 与运行，因此 CI 直接使用镜像自带的 `python3`。

## 1.0.21

- 修复崩溃 / 错误上报缺少 `app_channel` 与 `device_id` 两个字段（平台侧这两列始终为空）：`LogReporter.buildPayload()` 此前只组装 16 个字段，两个字段从未写入 payload。现在 `app_channel` 取自构建期常量 `BuildConfig.APP_CHANNEL`（release 构建为 `github`、debug 构建为 `dev`；重新打包的渠道包可用 `-PappChannel=<值>` 或 `APP_CHANNEL` 环境变量覆盖，取值经 `[A-Za-z0-9._-]` 过滤，避免非法字符破坏生成的 Kotlin 字符串字面量），`device_id` 取 `Settings.Secure.ANDROID_ID`（64 位十六进制，按「应用签名 + 用户」隔离，不随卸载重装变化，恢复出厂或更换签名后变化）。`ANDROID_ID` 在少数机型 / 受管设备上可能为 null 或空串，此时退化为**首次运行生成并持久化**的随机 UUID 以保证字段非空——持久化用 `commit()` 而非 `apply()`，因为崩溃路径上进程随时可能结束，异步落盘会导致下次启动换一个新标识、把同一台设备统计成两台；该 UUID 存于独立的 `log-report` 偏好文件，不经 `SettingsStore`，因此不会出现在设置快照与 MCP `app_config` 中。两处 Android lint 提示（`HardwareIds` / `ApplySharedPref`）以 `@SuppressLint` 显式豁免并注明理由，避免在既有 lint 基线上新增噪声。
- 同步隐私告知与设置页采集范围文案：`privacy_consent_body`（中英两套 strings）与审计页「崩溃与错误自动上报」分组说明各新增「匿名设备标识 / anonymous device identifier」与「分发渠道 / distribution channel」两项。设备标识属新增采集项，若不同步告知，新增字段就会落在 #100 建立的知情同意范围之外。
- 验证方式（不涉及本地构建）：改动文件过 ktlint 1.8.0（`--relative`）零违规；行宽按 **字符数**（而非字节数）复核，最长新增行 122 字符，未超 `.editorconfig` 的 160 上限——注意 `awk length()` 按字节计数，对中文会虚高约 3 倍，判定行宽必须用字符计数。
- APK MCP 桥接的「持续自动探测」改为默认开启：存储默认值由 `false` 翻转为 `true`，并新增一次性 `apkAutoProbeDefaultMigrated_v2` 迁移把升级用户的旧默认（曾被 1.0.x 强制关闭）重新翻回开启；用户仍可在设置页手动关闭。
- 修复 CI：`build.yml` 的「Set up Go」步骤里残留了一行 `uses: actions/setup-go@v5`，与升级后的 `@v7` 在同一 mapping 内构成 YAML 重复键，整个工作流文件因此无法解析，`main` 上每次 push 触发的运行都在启动阶段就失败（0 个 job，运行名退化成文件路径 `.github/workflows/build.yml`）。删掉残留行后 push 触发恢复正常。
- 修复 Unidbg 动态模拟完全不可用的问题（issue #91）：APK 里打包的 `libunicorn.so` 从来都不是 unidbg unicorn2 后端需要的那个库。unicorn2 后端（`com.github.unidbg.arm.backend.Unicorn2Backend` 调用 `com.github.unidbg.arm.backend.unicorn.Unicorn`）是 JNI 绑定，要求 `libunicorn.so` 导出 `Java_com_github_unidbg_arm_backend_unicorn_Unicorn_*`；而此前编出来的是「原始 unicorn 引擎」，只导出 `uc_*` C API。雪上加霜的是 `-DUNICORN_ARCH=arm,aarch64` 用了逗号——CMake 架构列表的分隔符是分号，于是 `arm-softmmu` / `aarch64-softmmu` 两个后端根本没参与编译，产物只有约 54 KB，是一个「只有 API 外壳、没有模拟核心」的空库。
- 这个坏库的危害在于它「看起来是好的」：`System.loadLibrary("unicorn")` 能成功，`system_control(action=status)` 也一直显示已随包内置，直到真正打开会话才失败——`Unicorn2Backend` 绑定不到 native 符号，而 `BackendFactory.newBackend` 因为应用以 `Unicorn2Factory(true)` 注册会吞掉这个异常，回退到旧版 `UnicornBackend`，后者随即抛 `NoClassDefFoundError: unicorn.Unicorn`（1.0.21 只带了一个精简的 `unicorn.UnicornException`），最终表现为「Unidbg 不可用」，并把排查引向 R8/ProGuard 方向。
- 修复 `build-unidbg-native.sh` / `build-unidbg-native.ps1` 的 unicorn 构建：改用 unicorn 2.x 引擎（`third_party/unicorn-engine-unicorn2`）编出 all-in-one `libunicorn.a`，再用 NDK 编译并链接 unidbg 自带的 JNI 桥（`backend/unicorn2/src/main/native/unicorn.c`）产出真正的 `libunicorn.so`，步骤与 unidbg 官方 `backend/unicorn2/src/main/native` 的构建方式一致；32 位 ABI（armeabi-v7a / x86）仍因 QEMU 需要 `__uint128_t` 而跳过 unicorn。
- 新增 `tools/verify_unicorn_jni.py`（可直接校验 `.so` 或 Release APK），并在两个构建脚本中作为硬性门槛：导出不了 unicorn2 JNI 桥的 `libunicorn.so` 一律拒绝安装，宁可让构建失败，也不再发出「自称可用、实则不可用」的包。
- 修正诊断信息：`system_control(action=status)` 的 `coverageModel` 新增 `backendInitError`，`UnidbgEmulator.unavailableReason()` 现在会区分「库没打进包」与「库在但不是 unicorn2 JNI 桥」，避免再次被误导。
- 修复前台服务被系统后台重启时必崩的问题（`ForegroundServiceStartNotAllowedException`，1.0.21(22) 现网崩溃报告，Android 16 / Samsung SM-S9110）：服务声明为 `START_STICKY`，进程被杀后系统会在应用处于后台时以 null Intent 重启它（崩溃报告顶部的 `Unable to start service ... with null` 即该路径），此时 `startForeground()` 因 `mAllowStartForeground=false` 被平台拒绝直接抛异常，且系统每轮按退避重启都会再次崩溃，构成崩溃循环。现在 `McpForegroundService` 把 `startForeground()` 包进 try/catch（捕获其父类 `IllegalStateException`——具体异常类 API 31 才存在，父类引用在旧系统上同样安全；另捕获 `SecurityException` 覆盖权限被回收的场景），被拒时记录日志、`stopSelf()` 并由 `onStartCommand` 返回 `START_NOT_STICKY`，系统停止重试这个永远无法满足的启动；服务器启动失败（如端口占用）同样返回 `START_NOT_STICKY`，不再无限重启。
- 顺带消除同一路径上的姊妹崩溃：完整性校验失败分支此前在 `startForeground()` 之前就 `stopSelf()`，违反 `startForegroundService()` 的平台契约（必须先进入前台才允许自行销毁），会被系统以 `RemoteServiceException: Context.startForegroundService() did not then call Service.startForeground()` 击落。现在 `startForeground()` 一律先执行，再走完整性校验与服务器启动逻辑。
- 接入 log-report-platform 的崩溃 / 错误自动上报能力：新增 `app/src/main/java/com/soreverse/mcp/core/LogReporter.kt`，按该平台的 `/api/v1/report` 协议（仅用 `HttpURLConnection`，零额外依赖）上报未捕获崩溃与手动错误。默认开启，开箱即上报至默认服务器 `https://api.somcp.cn`；用户仍可在设置页关闭。崩溃日志先落盘到本地队列（`logreport-queue`）再尽力即时上报；若进程在发送前被杀，下次启动 `LogReporter.init()` 自动补传残队。已与现有 `CrashReporter` 对接（`CrashReporter.install` 的未捕获处理器会调用 `LogReporter.reportCrash`），并新增 `SettingsStore` 两项配置（`crashReportEnabled` / `crashReportEndpoint`）同步进 `snapshot` / `applyPatch` / `schema`，可通过 MCP `app_config` 读写。
- 捕获型错误（`AppLog.e`）接入自动上报：`AppLog.e(message, throwable)` 现在把捕获到的错误（含异常堆栈）转发到 `LogReporter.report(logType="error", tag="AppLog.e")`，随同一开关生效；上报调用包在 `runCatching` 中，绝不会因上报失败影响业务。`LogReporter.report` 新增 30 秒重复指纹抑制（相同 `logType|tag|content` 只放行一次，最多保留 64 条指纹），避免重试循环等高频错误刷爆服务端；崩溃上报 `reportCrash` 不受抑制，确保每条崩溃都送达。
- 上报服务端定为 `https://api.somcp.cn`：将 `crashReportEndpoint` 默认值设为 `https://api.somcp.cn`，开启开关后即直接上报至默认服务器。
- 上报 API Key 改为**构建期注入 native 层**、不作为用户设置：`app/generate_header.py` 从环境变量 `LRP_API_KEY`（对应 SOMCP 仓库 Secret）读取密钥，XOR 混淆后写入 native 头 `key_generated.h`（由 `signature_verify.cpp` 编译进 `librz_native.so`），并新增 JNI `SignatureVerifier.nativeGetReportingApiKey()` 在运行期解码取回；`LogReporter.sendBlocking` 据此发送 `X-API-Key` 请求头。密钥只存在于混淆后的 native 二进制与 `X-API-Key` 请求头，不进 `BuildConfig` / `SettingsStore` / 设置快照 / MCP `app_config`，且不出现在任何日志：`generate_header.py` 不再打印密钥（TM 密钥的打印也一并脱敏）、CMake 仅报告是否注入而不打印值、密钥不进入任何命令行参数、CI 对 Secret 自动脱敏。`build.yml` 与 `release.yml` 的 `assembleRelease` 步骤已注入 `LRP_API_KEY` 环境变量（CMake 通过继承的环境读取，无需改动 Gradle）。
- 设置界面彻底不再出现上报密钥：移除审计页「崩溃与错误自动上报」分组说明文案中残留的「无需 API Key / no API key」措辞（密钥为构建期注入，非用户配置项，不应在 UI 中被提及）；全仓确认设置页无任何 API Key / `LRP_API_KEY` 字样与输入项。
- 修复 `SettingsStore.snapshot()` 中 `reporting` 分组的语法损坏：此前一次编辑残留了重复的 `.put("reporting",` 片段（`app_config action=get` 路径无法编译），已修正为标准的 `JSONObject().put("crashReportEnabled", …).put("crashReportEndpoint", …)` 结构。
- 上报服务器地址默认填入 `https://api.somcp.cn`：新增常量 `SettingsStore.DEFAULT_CRASH_REPORT_ENDPOINT`（单一来源），`crashReportEndpoint` 读取时对「键缺失」与「已存空串」两种情况统一回退到该默认值，因此审计页的服务器地址输入框始终预填 `https://api.somcp.cn`，无需用户手动输入；输入框占位符改为引用同一常量。上报开关默认开启，开箱即发往该地址。
- 「崩溃与错误自动上报」开关改为**默认开启**：`SettingsStore.crashReportEnabled` 存储默认值由 `false` 翻转为 `true`，配合默认端点，安装后无需任何配置即会上报未捕获崩溃与捕获型错误；用户仍可在审计页关闭。开关仅在用户手动切换时写入偏好的存储键，未交互的用户读到的是新默认值，因此无需额外迁移。
- 上报增加**隐私合规闸门**：新增 `SettingsStore.crashReportConsentAnswered`（默认 `false`）记录用户是否已就上报隐私告知作出选择，`LogReporter.config()` 改为以 `crashReportEnabled && crashReportConsentAnswered` 判定是否上报——**用户作出选择前不外发，也不写本地补传队列**。首个启动流程在现有免责声明之后新增一次性隐私告知弹窗（`MainActivity`，文案见 `privacy_consent_*` 字符串）：点「同意」即开始上报，点「不允许」则关闭开关并清空未发送的补传队列（新增 `LogReporter.clearQueue()`）。弹窗明示上报内容（崩溃/错误日志 + 设备型号、系统版本、CPU 架构、应用版本、包名）、传输方式（HTTPS）、用途（仅排查缺陷）与撤回方式（设置中随时关闭）。状态为「未询问 / 已同意 / 已拒绝」三态，由 `crashReportConsentAnswered` 与 `crashReportEnabled` 组合表达，并同步进 `snapshot` / `applyPatch` / `schema` / MCP `app_config`；在设置页主动开启开关亦视为同意。审计页说明文案同步补充了采集范围。
- 修复 CI 全部工作流的 `sdkmanager` 失败：`android-actions/setup-android@v3` 的 `packages` 输入默认值是 `tools platform-tools`，而 Google 已把 legacy `tools` 包从 SDK 仓库下架，`sdkmanager tools` 现在以 `Warning: Failed to find package 'tools'` 配合退出码 1 失败，该步骤因此在任何构建步骤之前就中断（`Test v7` 运行 34959565456 的第 5 步 `Run android-actions/setup-android@v3`）。9 个用到该 action 的工作流（`build.yml` / `release.yml` / `test.yml` / `test-v2.yml` ~ `test-v7.yml`）统一显式传入 `packages: platform-tools`。证据：`dl.google.com` 的 `repository2-1.xml` / `repository2-2.xml` / `repository2-3.xml` 中都不再有 `path="tools"` 条目，而 `path="platform-tools"` 仍在；同一工作流 09-13 的成功运行（34739543115）里该步骤还在解压 `tools/support/typos-*`，说明这是上游仓库侧的近期变更，与本仓库代码无关。
- 上报补传队列改为逐条独立处理：`LogReporter.flushQueue()` 此前是「发送成功才 delete，失败即 return」，队列里只要有一条失败，排在它之后的所有崩溃日志都不会再被尝试，下次启动又重复同样的行为。现在 `sendBlocking` 返回 HTTP 状态码（连接层失败返回 `-1`），补传循环对每条文件独立 `try/catch`：2xx 送达即删除；JSON 损坏的文件直接丢弃且不阻断后续；服务器已应答但拒绝（4xx / 5xx）时保留该文件并继续尝试后面的条目，避免一条永远失败的记录压住整个队列；只有连接层失败（网络 / 服务器不可达）才中止整轮，避免对剩余文件逐个空等 15s 连接超时。
- 上报 API Key 只在 release 构建附带：`sendBlocking` 此前对 debug 与 release 一律发送 `X-API-Key`。由于密钥由构建期注入 native 层，本地开发若在 `local.properties` 里配了 `lrpApiKey`，调试包便会带着生产密钥，而调试包往往会被自由分发。现在该请求头仅在 `!BuildConfig.DEBUG` 时附加，密钥仍不进日志、不改动注入链路、不进请求 body。
- 重复上报抑制改用单调时钟：`LogReporter.shouldSuppress` 的 30s 窗口此前基于 `System.currentTimeMillis()`，设备时钟被手动修改或 NTP 回拨时窗口可能被异常放开或误抑制，现改用 `SystemClock.elapsedRealtime()`。

- 修复 `Test v7` 的「Build Blutter runners (best-effort)」步骤从未产出过任何 runner 的问题（运行 34964948594 / 34739543115 的第 18 步）：该步骤每轮都是 `"built": 0`、8 个 runner 全败，因为标了 `continue-on-error: true` 而一直静默。两个根因都在本仓库的 overlay 里，与 Dart 上游无关：
  - `tools/blutter-matrix/android-runner/dart-app-accessors.patch` 用了零上下文 hunk（`@@ -29,0 +30,2 @@`）。`git apply` 没有上下文行就无法给 hunk 定位，只能把整个 hunk 追加到文件末尾，于是 `Libraries()` / `Classes()` 落到了 `DartApp` 类体之外（`};` 之后），CI 上表现为 `DartApp.h:88:47: error: non-member function cannot have 'const' qualifier`、`DartApp.h:88:62: error: use of undeclared identifier 'libs'` 以及 `classes` 的同类报错（共 6 个）。改为带真实上下文行的 hunk（`@@ -27,6 +27,8 @@`），两个访问器回到 `public:` 段内的第 30/31 行、`};` 之前。原补丁的 `index 59f7017..bb75511` 行与上游 `528acbe` 的实际 blob sha1（`a61081d`）并不匹配，属失效元数据，一并去掉；行尾同时从 CRLF 改为 LF——实测零上下文 hunk 即使去掉 `\r` 也同样落到文件末尾，即 CRLF 不是本次错位的原因，但它会让任何带上下文行的 hunk 在 Linux 侧因 `\r` 匹配不上而失败，属必须一并清掉的隐含缺陷。
  - `tools/blutter-matrix/android-runner/dart_vm_atomic_ref_compat.h` 的 `load()` / `exchange()` 用 `T result;` 作为 `__atomic_*` 的落地缓冲。`DEFINE_COMPRESSED_POINTER` 生成的 `Compressed*Ptr` 类型**没有默认构造函数**（与 `DEFINE_TAGGED_POINTER` 生成的 `klass##Ptr()` 不同），因此 Dart 3.12.2 起的 DartVM 交叉编译在 `tagged_pointer.h` 展开处失败：`error: no matching constructor for initialization of 'dart::CompressedTypedDataPtr'`，同类共 9 个错误（涉及 `CompressedFunctionPtr` / `CompressedArrayPtr` / `CompressedTypedDataPtr` 等）。改为写入 `alignas(T)` 的原始存储再按字节拷回——`T` 是 trivially copyable，这是拷回合法的依据。3.11.5 未受影响，因为该版本只在未压缩指针路径上实例化这两个方法。
  - 验证方式（不涉及本地构建）：把 shim 的类改名为 `std::atomic_ref_shim` 以强制其代码体生效（本地 NDK 29 的 libc++ 已带 `__cpp_lib_atomic_ref`，不强制就测不到；CI 实际用的 NDK 27.3.13750724 的 libc++ 18 没有该特性，所以 shim 在 CI 上确实生效），再用 NDK clang++ `--target=aarch64-linux-android26 -std=c++20` 编译同形态最小复现：修复前逐字复现 CI 报错（含 `candidate constructor not viable: requires single argument 'uncompressed', but no arguments were provided` 与隐式拷贝 / 移动构造的两条说明），修复后 `-O2 -Wall -Wextra` 零告警，且 `exchange()` 仍生成真正的原子交换 `__aarch64_swp4_acq_rel`。补丁部分用上游 `DartApp.h`（`528acbe`）在临时仓库里跑 `git apply --check` + `git apply`，确认落点由文件末尾回到类体内的第 30/31 行。
  - 保留 `continue-on-error: true` 与「best-effort」语义不变：这一步仍然只在完全成功时才把重新生成的 `runners.json` / `libblutter_*.so` 装进 `app/src/main`，失败时不动已提交的产物。
- 修复 `LLM Auto-Review PRs` 工作流在 CI 变慢后必定失败的缺陷（运行 34970157495 的 `review` job）：`Wait for CI checks and capture results` 步骤把自身硬超时设成与内部轮询窗口完全相同的 90 分钟（`timeout-minutes: 90` 与 `MAX_WAIT=5400`），于是只要 CI 用满窗口，动作就会被在窗口边界硬杀并让整个 job 失败——而步骤内本来就有 `ci_state=timeout` 的优雅降级分支（超时后继续做纯静态审查），这段兜底代码永远没有机会执行。该缺陷在 Blutter 修复后第一次暴露：`Test v7` 的 `checks` job 因真正开始编译 DartVM 而从 ~16 分钟升到 98.7 分钟（native backends 44.4 分钟 + Blutter runners 31.5 分钟），超过 90 分钟窗口，`review` job 在第 90 分钟被判超时而失败（后续 4 个步骤全部 skipped）。现把轮询窗口放宽到 180 分钟（`MAX_WAIT=10800`）、步骤超时设为 195 分钟，并保证两者之间留出余量，使「CI 比窗口更慢」只会走到优雅降级而非判失败。
- 修复 Blutter runner 矩阵里 Dart 3.13 / 3.14 变体全部编译失败（8 个变体只产出 2 个）的问题。上游基线由 `528acbe83b`（2026-04-26）升到 `4a60ac648b`（2026-08-18，含上游 PR #217「Fix ARM64 analyzer assertion on Dart 3.11+ leaf runtime call」），并在其上新增本地补丁 `tools/blutter-matrix/android-runner/dart-single-snapshot.patch`，内容即上游 PR #213（Add Dart 3.13 single-snapshot support，尚未合并）的原始 diff。
- 根因是 Dart 3.13 起移除了 VM isolate，blutter 的代码前提随之失效：`OBJECT_STORE_STUB_CODE_LIST` 宏不复存在，`DartStub.h:14` 报 `expected '= constant-expression' or end of enumerator definition`，并连带出 `use of undeclared identifier 'DO'`、`no member named 'InitAsyncStub' / 'DefaultTypeTestStub' / 'ArrayWriteBarrierStub' … in 'DartStub'`（枚举名整体从 `XxxStub` 变成 `XxxVMStub`）等 17 处错误；此外快照符号由 4 个（`_kDartVmSnapshotData` / `_kDartVmSnapshotInstructions` / `_kDartIsolateSnapshotData` / `_kDartIsolateSnapshotInstructions`）合并为 2 个（`_kDartSnapshotData` / `_kDartSnapshotText`），`dart::ObjectStore` 不再有 `throw_stub` 与 `HasBeenInitialized`，`AOT_Closure_context_offset` 之类的固定偏移量也已消失——后三者正是 `DartApp.cpp:318/323` 与 `CodeAnalyzer_arm64.cpp:1993/2042` 报错的来源。
- 补丁自带版本自适应开关，不需要按 Dart 版本传参：`pch.h` 用 `#ifdef kSnapshotDataAsmSymbol` 判定（该宏只出现在 Dart 3.13+ 的 `runtime/include/dart_api.h`，3.12.2 及其之前是 `kVmSnapshotDataAsmSymbol`），命中则定义 `BLUTTER_DART_SINGLE_SNAPSHOT`；DartStub.h、DartApp.cpp、DartLoader.cpp、ElfHelper.cpp、FridaWriter.cpp、CodeAnalyzer_arm64.cpp 的改动全部包在该宏内，因此 Dart 3.12 及更早版本仍走原始代码路径，原有 2 个变体的行为不变。
- 同步更新：`matrix-config.json` 的 `blutterCommit`、`build_runner.py` 的 `UPSTREAM_COMMIT` 与补丁应用序列（改为按序 apply `dart-app-accessors.patch`、`dart-single-snapshot.patch`，各带 `--check`）、`verify_manifest.py` 的上游基线校验值、`docs/blutter-backend.md` 的清单示例与基线说明。
- 验证方式（不涉及本地构建）：在临时仓库检出 `4a60ac648b`，两个补丁 `git apply --check` 与正式 `git apply` 均通过且互不冲突（改动区域无重叠——补丁改 `CodeAnalyzer_arm64.cpp` 的 1988/2020/2141 行，上游 ldur 修复在 677 行）；落点断言：`Libraries()` / `Classes()` 位于 `DartApp.h` 第 30/31 行（类体内、`};` 之前），`#define BLUTTER_DART_SINGLE_SNAPSHOT 1` 位于 `pch.h` 第 45 行（紧随 `#include <include/dart_api.h>` 之后，故该宏可见），`dart::StubCode::Throw()` 位于 `DartApp.cpp` 第 305 行。
- 上游 PR #213 一旦合并，可直接删除 `dart-single-snapshot.patch` 并改为引用其所在提交。已提交的产物 `app/src/main/assets/blutter/runners.json` 仍记录旧基线，需等下一次 runner 构建成功（CI 的 best-effort 步骤不提交产物）才会带上新 commit。
- 修复 `LLM Auto-Review PRs` 审查表格中「CI 检查失败」一行被错误归因的问题（PR #103 的两条审查记录）：该行的 `严重程度 / 文件 / 行` 此前完全由模型自由填写，于是模型把 CI 失败记到了 diff 里恰好出现的文件上——同一类问题两次分别渲染成「警告 / `CHANGELOG.md` / 12」与「严重 / `CHANGELOG.md` / 1」，而 PR #77 的正确形态是「严重 / `CI/CD` / 0」。CI 失败不是某个源码文件的缺陷，行号对它也没有意义，现在这一行改由工作流确定性产出，不再依赖模型自觉。
- 落点有三处：一是系统提示词明确要求 CI 相关 issue 的 `severity` 必须是 `critical`、`file` 固定填 `CI/CD`、`line` 填 0（不得指向 diff 中的具体文件）；二是 post-processing 增加归一化步骤，凡 `comment` 同时命中 CI 关键词（`CI` / `GitHub Actions` / `check-run`）与失败关键词（`failure` / `失败` / `未通过` / `红灯` / `错误` / `报错`）的条目，一律改写为 `critical` / `CI/CD` / 0 —— 只纠正归因字段，模型给出的具体分析文字（例如 PR #77 那条「确认是否存在编译错误」的提示）原样保留；三是 CI 红灯而 `issues` 中没有任何 CI 条目时补一行，确保失败项不会在表格里彻底消失。原先写在 CI 降级分支里的那条补行（`file` 为空串，渲染出来是一对空的代码反引号）随之删除，改由同一次归一化统一产出。
- 归一化可能把个别条目的严重程度从 `warning` 提升为 `critical`，因此随后追加一次 `critical > warning > info` 的稳定排序，以维持提示词里「issues 按严重程度从高到低排列」的约定。
- 验证方式（不涉及本地构建）：把工作流内嵌的 python 片段按 `PYEOF` heredoc 原样抽出并 `ast.parse` 做语法门禁，再以真实输入执行，断言 CI 行渲染为 `| 严重 | \`CI/CD\` | 0 |`。覆盖四种输入——CI 行被降级为 warning（PR #103 首轮）、CI 行 file/line 指向 `CHANGELOG.md:1`（PR #103 次轮）、approve + CI 红灯且模型未写 CI 行（降级路径）、CI 全绿——四例全部通过；同时确认 AGPL 合规行、`CHANGELOG` 范围行、代码行等非 CI 条目不被误判改写。
- 新增 `tools/check_pr_review_ci_row.py`，把上述验证固化为仓库内可重复执行的冒烟测试。归一化规则此前只存在于 `pr-auto-review.yml` 的 YAML 块标量里（`python3 - <<'PYEOF'` heredoc），整棵树没有任何地方能 import 或运行它，改动一次就可能静默失效、直到某次真实审查输出错误的归因而被发现。脚本从工作流中提取该 heredoc，先 `ast.parse` 做语法门禁——heredoc 被破坏时在本地立即失败，而不是等 CI 运行到该步骤才报错——再以冻结夹具执行，断言**整张表格逐行相等**。用例扩到 7 个：PR #103 两次审查的真实 issues 数组、approve + CI 红灯且模型未写 CI 行（须补行、把判定降级为 `request_changes` 并写下 `ci-downgraded` 标记）、CI 全绿时不得出现 CI 行、模型输出干扰（`issues` 里混入非字典条目、缺失 `severity`/`file`/`line`）、comment 提到 CI 但非失败时不得改写归因、多行 comment 先压成一行再判定。零网络、零密钥、零构建，`python3 tools/check_pr_review_ci_row.py` 一键执行，7/7 通过；未接入 CI 工作流——该测试的定位是本地冒烟，接入会连带触发多套构建矩阵，需要时再单独提出。

- 修复 `main` 上全部 push 型 CI 静默停跑的问题：`pr-auto-review.yml` 的自动合并调用 `pulls.merge` 时用的是本 run 的 `GITHUB_TOKEN`，而 GitHub 会抑制由该 token 触发的事件（例外只有 `workflow_dispatch` 与 `repository_dispatch`），因此被自动合并进 `main` 的提交，其 `push` 事件被静默丢弃——`Build & Sign APK`、`Test`、`Test v2` ~ `v7` 这些只监听 `on.push.branches: [main]` 的工作流一个 run 都不会被创建，界面上也没有红灯可看（不是失败，是压根没跑）。自 9/13 起 5 天内的 5 次合并（#100 ~ #104）全部没有跑过 APK 构建与测试矩阵，最后一次 `main` 上的构建还停留在 9/12。
- 证据链：PR #97（9/12，`merged_by = Hello666cpu`，真人合并）触发了 8 条 push 运行；PR #101 / #103 / #104（9/13 之后，`merged_by = github-actions[bot]`）各自 0 条 push 运行；`?branch=main` 的最近 30 条运行里，9/13 之后只剩 `schedule` 与 `issue_comment` 事件；tag push（`Release`）不受影响。旁证就在同一个文件里——原代码已经针对 `GITHUB_TOKEN` 抑制 `closed` 事件做过补救（在本 run 内自行关闭 linked issues 并生成关闭说明），只是漏了 `push` 同样被抑制。
- 修复方式为「补触发」：自动合并成功后依次对 `build.yml` / `test.yml` / `test-v2.yml` ~ `test-v7.yml` 调用 `actions.createWorkflowDispatch`（该接口正是官方例外之一，`GITHUB_TOKEN` 可以调用），触发分支取 `pr.base.ref`，单个工作流失败只记日志、不阻断合并流程。相应地 `permissions` 由 `actions: read` 提升为 `actions: write`，并给 7 个 test 工作流补上 `on.workflow_dispatch` 入口（`build.yml` 原本就有）。
- 换成 PAT / GitHub App token 合并的治本方案本次未采纳：它能让 push 事件恢复正常语义、未来新增的 push 型工作流也无需逐个补入口，但需要引入一个要人工轮换的仓库 Secret。两种路径的取舍已写进工作流注释，需要时可单独提出。
- 验证方式（不涉及本地构建）：对全部 13 个工作流文件跑严格重复键解析（PyYAML + 遇重复键即报错的 mapping 构造器），确认新增的 `workflow_dispatch` 没有破坏 `on` 段结构——13/13 通过；另把 `pr-auto-review.yml` 内嵌的 `actions/github-script` 脚本原样抽出跑 `node --check` 做语法门禁，避免改动在工作流运行时才报错。

## 1.0.17

本节仅记录 `1.0.16` 发布后到 `1.0.17` 发布之间的变化。

- 新增多 APK MCP 桥接并发支持，可同时连接 MT Manager 和 NP Manager 等多个桥接，通过工名前缀 `mt_apk_*` / `np_*` 路由到对应桥接，设置页提供添加/移除/状态指示 UI。
- 新增备份/恢复加密功能：可选 Argon2id 密钥派生（3 轮迭代，64 MiB 内存）+ AES-256-GCM 加密，支持密码保护、加密文件自动检测和导入密码提示；明文 JSON 导出仍为默认。
- 拓展 GitHub 下载加速镜像源：新增 9 个前缀代理镜像和 1 个域名替换镜像，前缀代理总数从 10 增至 19，域名替换从 2 增至 3。
- 修复 `probe()` 返回探针前快照而非探针后状态的问题，现正确返回所有探针完成后的实际连接状态。
- 修复 `ApkMcpBridge.probeUrl()` 在桥接离线时未保存配置的问题，用户可添加离线桥接稍后重试。
- 修复设置备份迁移缺失：新增一次性迁移，为 MT Manager 和 NP Manager 预填默认桥接 URL。
- 修复 Rizin 原生构建配置不可移植的问题（issue #17）：构建脚本不再硬编码机器路径，改为按脚本位置与环境变量（`ANDROID_NDK_HOME` / `ANDROID_HOME` / `MINGW_HOME`）自动探测工具链并支持参数覆盖；`build-rizin-all.ps1` 补齐 `arm64-v8a`（原缺失，导致该 ABI 设备 Rizin 反汇编不可用）；cross/native meson 配置文件模板化（`@NDK_ROOT@` / `@HOST_TOOLS@` 占位符）；内置 MinGW host 兼容补丁（Rizin v0.10.0 的 `_MSC_VER` / MSVC secure-CRT 兼容，幂等可跳过）；`CMakeLists.txt` 的 `RIZIN_SRC` 改为相对路径并加存在性校验。
- CI 调整：移除 test-v3 的 pull_request 触发，PR 默认使用 test-v6。

## 1.0.16

本节仅记录 `1.0.15` 发布后到 `1.0.16` 发布之间的变化。

- 修复在开启公网隧道后点击停止服务会卡死的问题：停止路径改为先同步拉起停止标记、再异步回收 cloudflared，避免主线程等待隧道退出而被卡住。
- 收紧快速隧道注册流程，停止时会中断仍在进行的请求，避免旧注册流程阻塞停止操作。
- 保留端口占用提示与原有启动失败反馈，避免把端口冲突误表现为无响应卡死。

## 1.0.15

本节仅记录 `1.0.14` 发布后到 `1.0.15` 发布之间的变化。

- 修复点击启动服务后首页状态未立即刷新为“运行中”的问题。
- 新增设置本地备份与恢复，可导出和导入 JSON 设置快照；密钥默认脱敏，仅在用户显式选择后包含或恢复。
- 修复 xAnSo 在 Android NDK 下因 Windows 专用头文件、`_itoa_s` 和 `va_list` 用法导致的构建失败。
- 审查并撤下未完成的 WebDAV/S3 远程备份，避免将凭据明文写入普通偏好设置或通过明文 HTTP Basic Auth 发送。
- 撤下会误判正式 APK 并终止进程的原生完整性实验实现，继续使用稳定的 APK 签名摘要校验与运行时检测。
- 清理重复的 CI 工作流，保留现有单元测试工作流。

## 1.0.14

本节仅记录 `1.0.13` 发布后到 `1.0.14` 发布之间的变化。

- 修复部分 MCP 客户端（如使用 rmcp 的客户端）握手失败的问题：`notifications/initialized` 等 JSON-RPC 通知此前被错误地返回了带 `id` 的响应，违反规范导致客户端报协议错误。现对所有通知（无 `id` 或 `notifications/*`）不再返回响应体，改回 HTTP 202 Accepted 空响应。
- 优化前台通知文案：允许局域网时不再显示 `0.0.0.0:8000` 这一容易被误当作访问地址的绑定通配符，改为直接给出可用的完整 MCP 地址（局域网 IP 或本机地址）并带上 `/mcp` 路径，避免用户误填 `0.0.0.0:8000/mcp` 而无法连接。

## 1.0.13

本节仅记录 `1.0.12` 发布后到 `1.0.13` 发布之间的变化。

- 修复 Rizin 原生分析并发导致的闪退：`rzFunctions` 等在多协程并发调用时，Rizin `RzCore` 非线程安全会在 `rz_core_free` 处 double-free 崩溃（Native SIGSEGV）。现将所有 `rz*` 原生入口统一串行化，同一时刻只允许一个 RzCore 存活。
- 举一反三：为 LIEF 原生层（parse/fixSections/patchAddress/getSectionContent/setSectionContent/addExportedFunction/removeSymbol 等）加入相同的进程级串行锁，消除同类并发崩溃风险。
- 修复更新下载切换加速源时的竞态：切源时旧下载协程可能仍在写同一临时文件并触发校验/回调，导致“镜像 A 下载中途变成 B”“A 下载校验完又用 B 重新下载”等异常。现对整个下载过程加互斥，切源会等待上一次下载完全结束后再开始，并在锁内复用已完成的校验结果，避免重复下载。
- 精简单元测试，仅保留守护关键逻辑（APK 内 SO 解析、下载源策略、Token 比较、签名摘要）的最小集合。
- 说明：fastjson 依赖仅由 unidbg 原生 MCP 工具在运行期通过反射使用，且不经过不可信 JSON 的 autoType 反序列化路径，不触发已知漏洞面；`org.json` 仍为项目主 JSON 库。

## 1.0.12（紧急补丁）

本节仅记录 `1.0.11` 发布后到 `1.0.12` 发布之间的变化。

> 致歉：`1.0.10`/`1.0.11` 出于安全考虑把默认绑定收敛为 `127.0.0.1` 并默认强制开启 Token，导致部分用户升级后局域网链接不显示、连接体验变差。这是我们在默认值取舍上的失误，给你带来的不便，深表歉意。本紧急补丁恢复为开箱即用的默认，并一次性纠正因更新而被写入的错误配置。

- 默认改为开启局域网访问（绑定 `0.0.0.0`）且默认不强制 Token；如需更严格的保护，可在设置中自行开启鉴权与绑定回环。
- 一次性纠正因 `1.0.10`/`1.0.11` 更新而被强制写入的错误配置（`127.0.0.1` + 强制 Token），升级后自动恢复为友好默认（仅执行一次，之后完全尊重用户自定义）。
- Cloudflare 隧道默认不再强制 Token：仅当用户自行开启鉴权时才要求设置访问 Token；未开启鉴权则按用户意愿启动，并给出公网暴露的明确提示。
- 下载更新时的 SHA-256 校验改为尽力而为，不再“吊死在一棵树上”：校验源限次数、带超时；校验源不可用/缺失时降级为“已下载有效 APK 但未校验”，不再卡很久或直接失败；仅当成功获取到校验值却不匹配时才判为失败。
- 更新下载的加速线路从“仅显示”改为“可手动切换”：测速中或下载中都可点选任一线路立即切换加速源，解决部分线路测速快但下载慢的问题。
- 下载缓存复用更稳健：此前已下载且结构有效的 APK 在无校验标记时也可复用，避免不必要的重复下载。

## 1.0.11

本节仅记录 `1.0.10` 发布后到 `1.0.11` 发布之间的变化。

- 修复 MCP 无法打开 APK 内 SO 的问题：重写来源匹配，新增纯函数解析 `apk:<相对路径>!lib/<abi>/x.so`、绝对路径 `App.apk!entry`、`content://apk/` 嵌套路径与裸 `lib/...` entry 四种等价写法，并按 apkPath/apkEntry 语义匹配，避免误报 `SO_NOT_FOUND`。
- 修复 1.0.10 引入的回归：默认绑定 `127.0.0.1` 时地址列表不再显示局域网链接（1.0.9 可显示）。现始终展示回环、局域网与可路由地址，绑定地址仅决定服务实际监听范围，不再从界面吞掉局域网地址。
- APK 内 SO 引用无法解析时返回更明确的提示，引导先用 `so_open (action=list)` 获取规范路径；APK 嵌入引用不再被错误当作越界文件路径，也不再对其做无谓的本地文件探测。
- 新增运行时溯源信息：MCP `initialize`、健康检查返回及"关于"页固定输出 AGPL-3.0 许可证、上游官方仓库、版权与再分发义务，作为可追溯、不易被抹除的来源标识。
- 强化开源合规声明：新增 `NOTICE`，README 增加带法律依据的再分发义务说明，关于页以《著作权法》《计算机软件保护条例》及 GPL 相关司法案例强化侵权告知。
- 新增维权材料：`docs/legal` 提供中英文 GPL 侵权告知函、论坛/网盘投诉与 GitHub DMCA 模板及证据固定清单。
- 新增 APK 内 SO 引用解析单元测试。

## 1.0.10

本节仅记录 `1.0.9` 发布后到 `1.0.10` 发布之间的变化。

- 复审并收敛 Cloudflare 永久隧道：新增更明确的永久隧道公网主机名/URL 提示、启动前 token 校验、协议参数透传，以及连接成功但尚未配置公网地址时的状态提示。
- 强化 Cloudflare 永久隧道错误处理：将更多认证/路由失败输出识别为终止性错误，避免无效重连并提示更新 token 或 Cloudflare 发布应用路由。
- 收紧远程配置修改：`app_config` 默认不再允许通过远程 patch 修改绑定地址、鉴权开关和隧道 token 等安全字段。
- 提升路径解析与工作目录提示：对绝对路径与 SAF 工作目录相对路径做更精确的匹配，并在未选工作目录或路径越界时返回可操作的错误。
- 修复 APK/工作目录读取的安全与稳定性边界：保留 APK 流式提取和 heap 预算限制，同时继续阻止不在允许目录范围内的本地 APK 输入。
- 优化通用鉴权与 UI 引导：token 校验保持恒时比较，设置页显式提示公网隧道必须先配置认证和 Cloudflare 发布应用地址。
- 审查开放 PR #7 与 Issue #5；吸收 PR #7 中可取的路径匹配与错误提示思路，但保持安全收敛，不接受会放宽边界的实现。

## 1.0.9

本节仅记录 `1.0.8` 发布后到 `1.0.9` 发布之间的变化。

- 修复 Cloudflare 永久隧道运行后不显示公网 URL：增加显式公网主机名/URL 配置、导入导出与状态展示，并允许连接成功后补写晚到 URL。
- 永久隧道遇到 `Unauthorized` 或 `Tunnel not found` 时立即熔断，不再无限重连；cloudflared 输出改为逐行读取并应用用户选择的日志级别。
- 修复 Android 16 `dataSync` 前台服务超时停止路径，显式移除前台通知并实现系统超时回调。
- APK 工作目录扫描和 APK 内 SO 提取改为流式处理，避免 63 MB APK 等输入被整体复制到 Java 堆后引发 OOM。
- 新增分析页资源清理入口，释放工作区、扫描索引、分页缓存和已结束的 Blutter 作业与结果。
- 修复更新 APK 校验失败后残留文件可能在下次被当作有效缓存的问题；下载改为临时文件、强制 SHA-256 校验并在成功后原子落盘。
- 修复事务批处理在快照创建失败后仍继续执行并可能回滚旧快照的问题，改为记录并回滚本次精确快照索引。
- 修复 Blutter 排队任务无法取消、文件描述符部分打开失败泄漏及结果摘要二次整文件读取造成的内存峰值。
- 修复关闭 APK MCP 工具合并后启动诊断仍强制要求桥接、快速切页短暂显示未连接，以及默认提示词按钮位置错误的问题。
- 审查 PR #4 与 #6；两者文件树重复且未提供 Dart 3.11.5 Runner，却允许使用 Dart 3.12.2 Runner 近似分析，因此不合并不安全实现并保持精确版本拒绝边界。

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
