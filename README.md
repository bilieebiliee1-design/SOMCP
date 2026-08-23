# SOMCP

SOMCP 是一个运行在 Android 手机上的本地 SO 逆向 MCP 服务器。它通过 Streamable HTTP 暴露 MCP 工具，让客户端可以在手机上完成 ELF 结构分析、Rizin 反汇编/分析、LIEF ELF 修复/重写、补丁会话、构建导出、Cloudflare Tunnel 暴露和可选 APK MCP 桥接。

当前版本：`1.0.19`

包名：`com.soreverse.mcp`

最低系统：Android 8.0 / API 26

许可证：`AGPL-3.0`。SOMCP 主项目依据 [GNU Affero General Public License v3.0](LICENSE) 发布。仓库中的第三方依赖、submodule、生成资源和补丁仍分别遵循各自上游许可证，AGPL-3.0 声明不会替代其原有许可条款。

> **再分发义务（重要）**：本软件受《中华人民共和国著作权法》与《计算机软件保护条例》保护。任何再分发（含修改、改名、二次打包版本）必须：保留版权与许可声明及 [NOTICE](NOTICE)、继续以 AGPL-3.0 授权、向每一位接收者提供完整对应源代码、并标注所做修改。闭源分发、抹除署名或改名冒充原创即构成侵权——依 AGPL-3.0 第 8 条授权自动终止，权利人可要求停止侵害、下架、公开更正并索赔（GPL 在中国司法实践中已被确认有效可强制执行，参见"数字天堂诉柚子科技""罗盒诉风灵"等案）。维权模板见 [docs/legal](docs/legal)。本软件在 MCP `initialize`/健康检查返回与"关于"页固定输出许可证、上游仓库与版权，作为运行时溯源证据。

## APK 位置

Release 构建输出目录：

```text
app/build/outputs/apk/release/
```

普通 arm64 手机优先安装：

```text
app/build/outputs/apk/release/app-arm64-v8a-release.apk
```

不确定 ABI 时安装：

```text
app/build/outputs/apk/release/app-universal-release.apk
```

## GitHub 更新

应用只通过 `bilieebiliee1-design/SOMCP` 的 GitHub 正式 Releases 检测更新。普通提交、分支、构建产物和未发布 tag 都不会被视为更新，draft 与 prerelease 也不会进入自动更新通道。

推荐 Release tag 使用 `v<versionName>`，并上传按 ABI 命名的 APK：

```text
SOMCP-1.0.19-arm64-v8a.apk
SOMCP-1.0.19-armeabi-v7a.apk
SOMCP-1.0.19-x86.apk
SOMCP-1.0.19-x86_64.apk
SOMCP-1.0.19-universal.apk
```

可同时上传同名 `<apk>.sha256` 或统一的 `SHA256SUMS`。检测器会优先选择当前设备 ABI，存在校验资产时会在安装前强制验证 SHA-256。

Release 输出体积随原生后端更新变化，以 GitHub Release 资产页面为准。

## 核心能力

- Android 原生前台服务，不依赖 Python 运行环境。
- Compose + Material 3 界面。
- Ktor CIO MCP HTTP 服务，默认端口 `8000`。
- MCP token 访问控制，可绑定 `127.0.0.1` 或 `0.0.0.0`。
- 通过系统文件选择器授权工作目录。
- 支持独立 `.so` 与 APK 内 `lib/<abi>/*.so` 工作流。
- Rizin 原生后端：函数分析、CFG、xref、crypto 扫描、ESIL、字节搜索、反汇编、汇编。
- LIEF 原生后端：ELF 解析、section 内容读写、section header 重建、符号修改、地址 patch。
- 编辑会话：snapshot、rollback、undo、redo、check、audit、persist。
- 构建导出：自动改名/覆盖、patch report、多输出变体、镜像到工作目录。
- Cloudflare Tunnel：quick/named 隧道、keepalive、状态统计。
- 可选 Unidbg：`emulate_call`、`emulate_dump`。**注意**：Unidbg 的 Android 原生库（`libcapstone.so` / `libkeystone.so` / `libunicorn.so` / `libjnidispatch.so`）不随 Debug APK 内置，需自行交叉编译 unidbg 上游 native 并放入 `app/src/main/jniLibs/<abi>/` 后重新构建，或在设备上额外安装；**官方 Release APK（v1.0.18+）已内置 arm64-v8a / armeabi-v7a / x86 / x86_64 全部四个 ABI 的 Unidbg 原生库**，直接安装即可使用。库缺失时 `system_control(action=status)` 的 `emulation.setup` 会明确标注 `requires-extra-install`，`emulate_*` 调用返回 `EMULATOR_UNAVAILABLE` 并说明缺失原因，不会伪装成可用。
- 完全离线 Flutter AOT 分析：内置 Flutter 3.44.2–3.44.7 / Dart 3.12.2 arm64 Blutter Runner；其他版本返回明确的不支持信息。
- Cloudflare 永久隧道支持配置要展示的 HTTPS 公网地址；认证失败会停止重连并提示更新 token。
- APK 内 SO 使用流式扫描与按需提取，分析页可一键释放工作区、索引缓存和已结束的 Blutter 数据。
- 精简工具列表：默认只暴露核心 + meta 工具，完整能力通过 `meta_info(action=describe)` 发现。

## MCP 工具体系

当前目录共 38 个内置工具，默认 lean 模式会广告核心、底层网关和 meta 工具，降低 LLM 初始化上下文成本。

推荐工作流：

```text
so_open(action=list)
so_open(path=...)
analyze_elf(view=stats)
analyze_functions
read_disasm(locator=...)
session_open
edit_asm(dryRun=true)
session_history(action=check)
build_so
```

搜索语法：

```text
search_bytes(pattern="5F2403D5")          # Rizin 原生 byte pattern，紧凑 hex
search_bytes(pattern="5F24..D5")          # Rizin nibble 通配符，. 表示任意半字节
search_bytes(pattern="5F2403D5:FFFF00FF") # Rizin bytes:mask
search_bytes(pattern="5F 24 ?? D5")       # MCP 兼容写法，会规范化为 5F24..D5 后交给 Rizin
search_strings(prefix="JNI.*Load", regex=true)
```

AI 调用注意事项：

- `so_open`、`search_bytes`、`analyze_*`、`read_disasm` 等重型工具受全局并发闸门保护；自动化客户端应串行调用，遇到 `SERVER_BUSY` 按 `retryAfterMillis` 重试同一请求。
- `search_bytes` 优先使用 Rizin 搜索；返回的 hit 会包含 `addr`、`hexAddr`、`fileOffset`、`section`、`sectionOffset`，可直接衔接 `read_hexdump` 或 patch 工具。
- `search_strings(regex=true)` 使用 Kotlin 正则；非法正则会返回结构化错误，不会被当作空结果。
- 电脑侧直接调用手机 MCP 时可先执行 `adb forward tcp:8000 tcp:8000`，然后使用 `http://127.0.0.1:8000/mcp`。

工具发现：

```text
meta_info(action=help)
meta_info(action=tools)
meta_info(action=describe, tools=["edit_asm", "build_so"])
meta_info(action=workflows)
meta_info(action=suggest, workspaceId="...")
meta_info(action=errors)
meta_info(action=report, workspaceId="...", writeToFile=true)
meta_info(action=capabilities)
meta_info(action=health)
```

`meta_info(action=report)` 会生成完整分析报告，包含 ELF 统计、节区、动态符号、字符串、Rizin 函数、crypto 扫描和建议，并可落盘到 app 私有 reports 目录。

底层 API 通过 capability registry + 4 个聚合网关暴露，避免 MCP 工具数量爆炸。`meta_info(action=capabilities)` 是真实能力面来源，会明确列出 supported / partial / missing，避免把未实现的底层 API 误报为已覆盖：

```text
rizin_api(action=capabilities|command|analyze|functions|cfg|xrefs|search_bytes|crypto|esil|diff|asm|disasm)
lief_api(action=capabilities|parse|list|patch_address|add_export|remove_symbol|build|fix_sections|report)
unidbg_api(action=capabilities|status|call|dump)
xanso_api(action=capabilities|status|fix_sections)
flutter_blutter(action=inspect|analyze|status|result|cancel|packages|prune)
dynamic_api(action=capabilities|dispatch|status|analyze)
dynamic_analyze_ai(evidence=...|function=...|request=...)
```

## 动态分析（手动加载到内存 → AI 分析）

SOMCP 提供一套**独立**的动态分析工具流程，与静态 deep-analysis 循环彼此分离，把「把 `.so` 手动加载到内存 → 执行 → 采集证据 → 交给 AI 分析」串成一条可被 MCP 调用的链路。核心入口是两个工具：

```text
dynamic_api(action=capabilities|dispatch|status|analyze, op=unidbg_session_open|unidbg_session_call|unidbg_session_registers|frida_hook|frida_call|analyze, backend=unidbg|frida, targetFunction=...)
dynamic_analyze_ai(function=... | evidence=...)
```

两个后端共用同一套编排层 `dynamicDispatch`：

- **unidbg（模拟）**：`unidbg_session_open` 把选中的 `.so` 映射进模拟内存，`unidbg_session_call` 解析指定导出函数并执行，随后采集寄存器和目标地址的内存 dump。无需真机，适合快速验证目标函数行为。
- **frida（真机 hook）**：`FridaBridge` 以纯 Kotlin 实现 `frida-server`/`frida-gadget` 的 TCP 协议客户端，`frida_hook` 通过 JS agent（Interceptor/Module）挂钩目标函数捕获入参与返回，`frida_call` 触发调用并回读 hook 结果。**注意**：`frida-server`/`frida-gadget` 不随 APK 内置，需在已 root 设备上单独安装并在推开时先对目标进程 `ptrace`/注入；未就绪时 `dynamic_api(action=capabilities)` 的 `status.fridaAvailable` 会如实标注 `false`，不会伪装成可用。

`dynamic_analyze_ai` 复用 `RikkaAgentEngine`，把 `dynamicRun` 证据（寄存器现场、内存 dump、hook 记录、调用返回）喂给 AI 生成结构化动态分析报告：

```text
dynamic_api(action=capabilities)        # 查看 backends.dynamic，确认 unidbg/frida 可用性
dynamic_api(action=dispatch, backend=unidbg, op=unidbg_session_open, targetFunction="JNI_OnLoad")
dynamic_api(action=dispatch, backend=unidbg, op=unidbg_session_call, targetFunction="JNI_OnLoad")
dynamic_analyze_ai(function="JNI_OnLoad")  # 或直接传入上一步 evidence
```

`meta_info(action=capabilities)` 的 `backends.dynamic` 是动态分析的能力真实面来源，明确列出 unidbg/frida 的支持状态与限制。

`rizin_api(action=command)` 提供受控 Rizin raw command 通道，用于覆盖大量 Rizin 命令式底层能力；为安全起见，写入、文件、shell 等危险命令会被阻止。

批量流水线支持事务模式：

```text
meta_info(action=batch, transactional=true, steps=[...])
```

事务模式会在执行前为涉及 `workspaceId + editSessionId` 的编辑会话自动创建 snapshot；后续步骤失败时会自动 rollback 到事务前快照。

分页继续：

```text
meta_info(action=continue, cursor="page:...")
```

系统状态：

```text
system_control(action=status)
```

`health/status` 会返回运行时信息，包括 APK 版本、设备 ABI、nativeLibraryDir、`librz_native.so` 大小、mtime 和 SHA-256 短指纹，用于确认设备上实际运行的是不是最新 APK。

## 设置项

- MCP 访问控制：token、绑定地址、访问 URL。
- 返回数量：默认 limit、字符串 limit、反汇编窗口、hexdump、请求体上限。
- 导出：冲突策略、patch report、镜像到工作目录、patch 字节上限、构建产物列表上限。
- 编辑校验与审计：自动快照、审计日志、审计持久化、最大快照数、最大审计数、diff 范围数。
- 工具暴露：lean tools、自适应 lean、禁用工具列表、工具结果字符上限、工具调用频率限制。
- 性能保护：重型工具并发上限、请求超时、工具统计持久化。
- 原生执行：Unidbg 模拟执行开关。
- Blutter：查看内置 Flutter 3.44 / Dart 3.12.2 Runner、离线执行方式和精确兼容性规则。
- Cloudflare Tunnel：quick/named、目标端口、协议、IP 版本、日志等级、keepalive、重连退避。
- APK MCP 桥接：APK MCP URL、自动探测、工具合并、转发超时。

## 从零构建

准备环境：

- Windows 10/11
- JDK 17
- Android SDK 36
- Android NDK `29.0.14206865`
- CMake `3.22.1`
- Gradle `9.6.1`

获取 Rizin 源码（Rizin 反汇编/分析后端，非 git 子模块，需手动 clone 一次）：

```powershell
git clone https://github.com/rizinorg/rizin.git third_party/rizin-src
```

构建 Rizin / LIEF 原生依赖：

```powershell
.\build-rizin-all.ps1
.\build-lief-all.ps1
```

构建脚本不依赖任何固定机器路径：工具链通过环境变量解析（`ANDROID_NDK_HOME` / `ANDROID_HOME` 定位 NDK，`MINGW_HOME` / PATH 定位 MinGW 宿主编译器，`ANDROID_HOME` 定位 CMake/Ninja），也支持显式参数覆盖。例如：

```powershell
# Rizin：指定源码树 / NDK / 宿主 MinGW（任一均可省略，缺省自动探测）
.\build-rizin.ps1 -Abi arm64-v8a -RizinSrc D:\rizin-src -NdkRoot D:\Android\Sdk\ndk\29.0.14206865 -HostTools D:\mingw64
.\build-rizin-all.ps1 -RizinSrc D:\rizin-src   # 一次构建全部 4 个 ABI（含 arm64-v8a）
# LIEF：指定 CMake / Ninja / NDK
.\build-lief.ps1 -Abi arm64-v8a -NdkRoot D:\Android\Sdk\ndk\29.0.14206865
```

**关于 Rizin 的 host 编译器（build machine）**：Rizin 构建时需要用它生成少量 host 工具，Windows 下官方支持 MSVC，本构建脚本默认使用 MinGW-w64 作为 host（自动探测 `MINGW_HOME` / PATH，`-HostTools` 可覆盖），并会在 meson setup 前**自动对 Rizin 源码树应用幂等补丁**（`librz/util/` 下的 `file.c` / `time.c` / `sys.c` / `subprocess.c`：放宽 `_MSC_VER` 条件使其同时覆盖 MinGW 的 `__WINDOWS__`，并为 MSVC secure-CRT 的 `_wdupenv_s` / `_wputenv_s` / `_chsize_s` / `_snwprintf_s` 插入 MinGW shim）。这些补丁只改本地的 Rizin checkout，已打过则跳过，用 `-SkipPatch` 可关闭。若改用 MSVC host（需自行准备 VsDevCmd 环境并把 `rizin-native.ini` 指向 `cl.exe`），则无需这些补丁。

（可选）构建 Unidbg 模拟后端所需的 Android 原生库（capstone/keystone/unicorn，默认不内置，详见“核心能力”中 Unidbg 说明）：

```powershell
git submodule update --init --recursive
.\build-unidbg-native.ps1
```

构建 release：

```powershell
D:\Gradle\gradle-9.6.1\bin\gradle.bat :app:assembleRelease
```

验证原生库是否还有会导致 `dlopen` 失败的非系统未解析符号：

```powershell
.\verify-native-libs.ps1
```

如果输出全部为 `OK`，说明 Rizin/ZSTD/LIEF 等非系统符号已经在 APK 自带库内解析完毕。

## 安装与验证

建议先卸载旧包再安装，避免 Android 继续加载旧 native lib：

```powershell
adb uninstall com.soreverse.mcp
adb install -r app\build\outputs\apk\release\app-arm64-v8a-release.apk
```

启动 MCP 后调用：

```text
meta_info(action=health)
```

预期：

```json
{
  "nativeBackends": {
    "rizin": { "available": true, "loadStatus": "loaded" },
    "lief": { "available": true, "loadStatus": "loaded" }
  }
}
```

如果仍然报 `dlopen failed: cannot locate symbol ...`，请检查 `runtime.librzNative.sha256_16` 是否等于你本地最新 APK 中的 `librz_native.so` 指纹。

## Release 优化

Release 构建启用：

- R8 代码压缩和混淆。
- Android 资源压缩。
- ABI 分包 + universal 包。
- v1/v2/v3/v4 APK 签名。
- 严格 native 链接：禁止 Rizin/LIEF/zstd 未解析符号混入 `.so`。
- JNI keep 规则：保留 `RizinNativeEngine` / `LiefEngine` 的类名和 native 方法名。

## 注意事项

- 本项目采用 AGPL-3.0 许可证。任何再分发（含修改、改名、二次打包版本）必须：
  - 保留版权与许可声明；
  - 继续以 AGPL-3.0 授权；
  - 向每一位接收者提供完整对应源代码；
  - 标注所做修改。
  - 闭源分发、抹除署名或改名冒充原创即构成侵权，依 AGPL-3.0 第 8 条授权自动终止，SOMCP 项目组将依法提起诉讼以维护自身权益。
- 本工具只适合分析自己有权处理的文件。第三方二进制的逆向、修改和分发可能受法律、协议或平台规则限制。
- 汇编补丁更适合等长覆盖或明确边界内 patch，不会自动搬移后续代码。
- 手机无法单独证明自己从公网可访问；公网可达性需要远端客户端、Cloudflare Tunnel 或其他外部探测配合。
- APK MCP 桥接依赖 MT 管理器侧边栏 APK MCP 功能在线，并需要 MT 管理器保持后台运行。
