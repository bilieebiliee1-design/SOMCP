# SOMCP：Android 本地 SO 逆向 MCP 服务器

这段时间在整理一个 Android 原生版的 SO 逆向 MCP 工具，名字先叫 SOMCP。它的目标比较直接：把常用的 SO 查看、反汇编、字符串/符号检索和简单补丁能力放到手机本地跑，再通过 MCP 接给支持 MCP 的客户端使用。

它不是一个完整的 IDA/Ghidra 替代品，更像是一个轻量的 Android 端分析后端。适合在手机上临时看 SO、扫 APK 里的 native 库、让客户端按工具接口读取 ELF 信息，或者做一些边界明确的字节/汇编修改。

## 基本信息

- 应用名：SOMCP
- 包名：`com.soreverse.mcp`
- 版本：`1.0.0`
- 最低系统：Android 8.0
- 默认端口：`8000`
- 服务地址：`http://手机IP:端口/mcp`
- 构建方式：Android 原生 APK，不需要在手机上装 Python

## 主要功能

- 选择一个工作目录，扫描目录里的 `.so` 和 `.apk`。
- 可以识别 APK 内的 `lib/<abi>/*.so`。
- 提供 MCP HTTP 接口，客户端可以直接调用工具。
- 默认启用访问 token，支持绑定本机地址或局域网地址。
- 读取 ELF 头、节表、符号、动态符号、重定位、导入、字符串。
- 使用 Capstone 做 native 反汇编。
- 使用 Keystone 做汇编补丁。
- 支持十六进制补丁、符号名补丁、导出修改后的 SO。
- 前台服务运行，支持 WakeLock。
- 可开启悬浮窗，点击悬浮窗能直接回到主界面。
- 界面里会显示本机、局域网、IPv6 等可用 MCP 地址。
- 自带实时日志，方便看服务状态和工具调用情况。
- 扫描目录时会做文件指纹缓存，重复列表和打开同一个 SO 会少很多重复解析。
- APK 内 SO 列表和 ELF 摘要会写入 SQLite 缓存，重启 APP 后也能复用。
- 大结果支持 cursor 分页，客户端可以用 `mt_so_continue` 继续读取。
- 反汇编现在按字节窗口读取，支持 `byteOffset`、`maxBytes` 和 cursor，不会因为一个大函数就一次性反完整段。
- 同一个 workspace 的重复搜索会走缓存，反复查同一个字符串或符号时响应更稳。
- 重量级分析请求会串行执行，避免客户端并发请求把手机压满。
- 可以设置 MCP 请求体上限，客户端误传大内容时会直接拒绝。
- 主界面能浏览目录里的 SO、打开 APK 内 SO、看基础 ELF/JNI 摘要，也能查看已打开工作区、复制 workspaceId、关闭工作区。
- 编辑会话会记录补丁，构建时可选择生成 patch report，输出文件冲突时可自动改名或覆盖。
- 增加 `mt_so_diff` 和 `mt_so_analyze`，用于补丁复盘和基础 JNI/风险线索分析。

## APK 选择

release 会生成多个包：

```text
app-arm64-v8a-release.apk       常见 64 位手机优先用这个
app-armeabi-v7a-release.apk     老 32 位 ARM 设备
app-x86-release.apk             x86 模拟器或设备
app-x86_64-release.apk          x86_64 模拟器或设备
app-universal-release.apk       不确定 ABI 时使用，体积最大
```

当前构建出来的体积大概是：

```text
arm64-v8a    12.6 MB
armeabi-v7a  10.9 MB
x86          11.7 MB
x86_64       12.8 MB
universal    41.8 MB
```

普通手机基本都是 `arm64-v8a`。如果发给别人测试，又不想解释 ABI，就发 universal 包。

## 安装后怎么用

1. 安装 APK，打开 SOMCP。
2. 首次进入会看到免责声明，确认后进入主界面。
3. 点“选择目录”，选一个包含 `.so` 或 `.apk` 的目录。
4. 点“启动/停止”，启动 MCP 服务。
5. 在“MCP 链接”区域复制地址。默认复制出来的地址会带 token。
6. 把地址填到 MCP 客户端里，路径是 `/mcp`。

如果客户端和手机在同一个局域网，通常用这种地址：

```text
http://192.168.x.x:8000/mcp
```

如果是在手机本机调试，可以用：

```text
http://127.0.0.1:8000/mcp
```

默认启用了 token。也可以不把 token 放 URL 里，改用请求头：

```text
Authorization: Bearer <设置页里的 token>
```

如果只打算本机访问，可以在设置里把绑定地址改成 `127.0.0.1`，然后重启服务。

注意，手机自己不能证明“公网一定能访问进来”。公网访问需要远端客户端、端口转发、内网穿透或单独的外部探测服务。

## 推荐调用顺序

先列出可用 SO：

```text
mt_so_list_available_sos
```

打开目标：

```text
mt_so_open
```

查看概览：

```text
mt_so_list
mt_so_read_elf
mt_so_read_strings
mt_so_read_disasm
```

反汇编默认是窗口读取。大函数继续往后看，直接把返回里的 `pagination.nextCursor` 交给 `mt_so_continue`；需要从函数内部某个位置读，可以传 `byteOffset`；想控制单次反汇编工作量，可以调 `maxBytes`。

需要修改时，先开编辑会话：

```text
mt_so_edit_open
```

然后按需要使用：

```text
mt_so_edit_asm
mt_so_edit_hex
mt_so_edit_symbol
mt_so_edit_check
mt_so_build
```

导出的 SO 会放到应用外部文件目录里，界面日志里会显示路径。

构建补丁时还会生成：

```text
*.patch-report.json
```

里面包含 edit session、offset、原始字节、新字节、asm 文本和输出文件 checksum。也可以用：

```text
mt_so_diff
```

直接查看当前编辑会话的补丁记录和 byte diff。

基础分析：

```text
mt_so_analyze
```

会返回 `JNI_OnLoad`、`Java_*` 导出、`RegisterNatives` 线索、动态加载导入、crypto/ssl 导入，以及 URL、路径、命令字符串等信息。

分页读取：

```json
{
  "cursor": "page:..."
}
```

传给：

```text
mt_so_continue
```

工具说明：

```text
mt_so_help
mt_so_describe_tool
```

## 权限说明

应用会用到这些权限：

- 网络：启动本地 MCP HTTP 服务。
- 通知：前台服务必须有通知。
- 悬浮窗：显示运行状态，点一下能回到主界面。
- WakeLock：让服务在后台尽量保持运行。
- 电池优化豁免：部分国产系统后台限制比较强，长时间跑服务建议手动放开。

## 新增设置项

- 访问 token：默认开启，可以重新生成。
- 绑定地址：局域网访问或仅本机访问。
- 返回数量：默认 limit、字符串 limit、反汇编指令数、反汇编窗口字节数、hexdump 字节数、请求体上限。
- 导出策略：输出文件冲突时自动改名或覆盖，是否写 patch report。
- 扫描缓存：是否启用索引缓存、是否在列表里解析 ELF 摘要、是否扫描 APK、是否扫描子目录。
- 扫描范围：最大扫描深度、跳过大文件阈值。
- SO 浏览器：主界面可以扫描目录、打开 SO、查看 ELF/JNI/字符串数量等摘要。
- 工作区：主界面可以刷新、复制 workspaceId、关闭工作区。
- 客户端配置：可以复制 header token 配置，减少把 token 放 URL 里的情况。
- 日志：最低日志级别、暂停刷新、过滤、清空。

不同系统的后台策略不一样。如果发现服务过一会儿就断，通常需要在系统设置里允许自启动、后台活动、通知、悬浮窗，并把电池策略改成不限制。

## 从零构建

下面以 Windows 为例。

需要准备：

- JDK 17
- Android SDK 36
- Android NDK `29.0.14206865`
- CMake `3.22.1`
- Gradle `9.6.1`

安装 SDK 组件：

```powershell
& "$env:ANDROID_HOME\cmdline-tools\latest\bin\sdkmanager.bat" "platforms;android-36" "build-tools;36.0.0" "ndk;29.0.14206865" "cmake;3.22.1"
```

如果项目路径里有中文，建议把 Capstone 和 Keystone 复制到 ASCII 路径，避免老 CMake 工程在 Windows 上出问题：

```powershell
New-Item -ItemType Directory -Force -Path C:\tmp\sormcpdeps
Copy-Item -Recurse -Force third_party\capstone-5.0.6 C:\tmp\sormcpdeps\
Copy-Item -Recurse -Force third_party\keystone-0.9.2 C:\tmp\sormcpdeps\
```

生成自己的签名文件：

```powershell
New-Item -ItemType Directory -Force release
keytool -genkeypair `
  -v `
  -keystore release\so-reverse-mcp-release.jks `
  -alias so-reverse-mcp `
  -keyalg RSA `
  -keysize 2048 `
  -validity 36500
```

写入 `release/keystore.properties`：

```properties
storeFile=release/so-reverse-mcp-release.jks
storePassword=你的密码
keyAlias=so-reverse-mcp
keyPassword=你的密码
```

构建 release：

```powershell
D:\Gradle\gradle-9.6.1\bin\gradle.bat :app:assembleRelease
```

输出目录：

```text
app/build/outputs/apk/release/
```

校验签名：

```powershell
& "$env:ANDROID_HOME\build-tools\36.0.0\apksigner.bat" verify --verbose --v4-signature-file app\build\outputs\apk\release\app-arm64-v8a-release.apk.idsig app\build\outputs\apk\release\app-arm64-v8a-release.apk
```

正常会看到：

```text
Verifies
Verified using v2 scheme: true
Verified using v3 scheme: true
Verified using v4 scheme: true
```

## 构建优化记录

这版 release 做了几项比较实在的优化：

- 开启 R8 代码压缩。
- 开启资源压缩。
- 开启 ABI 分包，避免每台手机都安装四套 native so。
- native release 加了 `-Os`、section 裁剪和链接裁剪。
- 日志缓存从 CopyOnWrite 容器换成有界队列，频繁工具调用时少一些复制开销。
- APK 扫描不再把整包字节挂在每个 SO 条目上，减少大 APK 目录下的内存占用。
- 增加文件指纹缓存、SQLite 持久缓存、SO 摘要缓存和工作区复用，减少重复扫描和重复解析。
- 反汇编改成窗口读取，大函数按 `maxBytes` 分段处理。
- 重复搜索增加 workspace 级缓存，编辑后会自动清掉旧结果。
- MCP 请求体增加上限保护，减少误请求造成的卡顿。
- MCP 重工具串行执行，避免多请求同时跑反汇编、搜索、解析。
- 构建 patched SO 时可输出 patch report，文件名冲突可以自动改名，便于复盘和分享修改记录。
- 保留 universal 包，方便不确定设备 ABI 时分发。

体积变化比较明显。原来单个 universal release 包约 54.7 MB，现在 universal 约 41.8 MB；如果按手机常见的 arm64 包分发，只有约 12.6 MB。

## 限制和注意事项

- 只建议分析自己有权处理的文件。第三方二进制的逆向、修改、分发可能受到法律、协议或平台规则限制。
- `outline`、`xref_symbol`、`xref_string` 是移动端基础实现，别按完整桌面逆向套件的深度去期待。
- 汇编修改适合等长覆盖，或者调用方明确给出边界的覆盖修改；不会自动重排函数和修复复杂控制流。
- 公网访问不要只看手机本机探测结果，最好用真正的远端客户端测试。

整体上，这个工具更适合作为 MCP 客户端的 Android 本地分析后端。需要临时看 SO、批量扫 APK 里的 native 库、或者把一些简单逆向动作接进自己的工作流时，会比较方便。
