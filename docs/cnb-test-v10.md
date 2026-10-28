<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Test v10 的 CNB 版本

`.github/workflows/test-v10.yml`（GitHub Actions，757 行）检查项较多，
在 cnb.cool 上另有一份等价流水线，配置在 `.cnb.yml` 的 `Test v10` 里。
本文说明两边的对应关系、平台差异的处理方式，以及需要维护者补齐的东西。

源码侧的门禁（PR 自动审查、issue 自动回复、release）仍然只在 GitHub 上跑；
CNB 这份流水线的定位是「同一套构建与静态检查，在 CNB 上也能复现」，
不替代 GitHub 侧的任何工作流。

## 触发入口

| GitHub | CNB |
| --- | --- |
| `on.push.branches: [main]` | `main.push` 下名为 `Test v10` 的流水线 |
| `on.pull_request.branches: [main]` | `main.pull_request` |
| `on.workflow_dispatch` | `main.web_trigger.test-v10`（页面「自定义手动触发」，自定义事件名 `test-v10`） |

`main.push` 下还有一条既有的「同步到 GitHub 镜像仓库」流水线，两条并行执行、互不影响。

## 步骤对照

| # | GitHub step | CNB stage | 说明 |
| --- | --- | --- | --- |
| 1 | `actions/checkout`（`submodules: recursive`、`fetch-depth: 0`） | 代码准备阶段 + `校验代码准备` | submodule 由 `git.submodules` 显式声明；`fetch-depth: 0` 对应 CNB 本地已有完整历史；`scripts/cnb/setup-build-env.sh` 断言 `third_party/*` 全部非空 |
| 2 | `actions/setup-java`（temurin 17） | `基础镜像与工具链` | 镜像基于 `eclipse-temurin:17-jdk-noble`，setup 脚本断言 `java.specification.version == 17` |
| 3 | `gradle/actions/setup-gradle`（9.6.1，`cache-disabled`） | `基础镜像与工具链` | 镜像内装 Gradle 9.6.1、装用户级 init script（Maven Central 镜像）、预热插件与构建期依赖；用户目录挂 data 卷。见下方「Gradle 用户目录」与「Maven Central 限流」 |
| 4 | `android-actions/setup-android` + `sdkmanager` | `基础镜像与工具链` | 镜像内装 platform-tools / android-36 / build-tools 36.0.0 / ndk 29.0.14206865（另含 VMP 壳要的 android-34 与 cmake 3.22.1） |
| 5 | Determine base revision（`id: base-rev`） | `判定 base revision` | `scripts/cnb/base-rev.sh`，`CNB_EVENT` + `CNB_PULL_REQUEST_TARGET_SHA`，`##[set-output]` → `BASE_REV` |
| 6 | Check for empty PR | `空 PR 拦截` | `scripts/cnb/check-empty-diff.sh` |
| 7 | Profanity check | `脏话检查` | `scripts/cnb/check-profanity.sh`，PATTERNS 词表逐字照搬 |
| 8 | AGPL-3.0-only license compliance | `AGPL-3.0-only 合规检查` | `scripts/cnb/check-license.sh`，三条判据不变 |
| 9 | PR size check | `PR 规模检查` | `scripts/cnb/check-pr-size.sh`，>50 文件 / >2000 行只警告 |
| 10 | ktlint（1.5.0） | `ktlint 代码风格检查` | `scripts/cnb/check-ktlint.sh`，版本钉住 1.5.0，命令未改 |
| 11 | `gradle :app:lintDebug` | `Android Lint` | 原命令 |
| 12 | Install native build tools | `原生构建工具检查` | 见下方「无法逐字等价的项」 |
| 13 | Clone Rizin v0.9.1 | `克隆 Rizin v0.9.1 源码` | 原命令，`--depth 1 --branch v0.9.1` |
| 14 | Cache native backends | `原生后端缓存的失效判定` | 见下方「缓存」 |
| 15 | `bash build-native-android.sh` | `编译原生后端` | 原命令，timeout 4h |
| 16 | Blutter runners（`continue-on-error`） | `构建 Blutter runners` | `allowFailure: true`，timeout 6h |
| 17 | `gradle :app:assembleDebug` | `Debug 构建` | 原命令 |
| 18 | Restore keystore（或 CI 临时 keystore） | `恢复签名 keystore` | `scripts/cnb/prepare-keystore.sh`，四个 secrets 缺失时走 CI-only 分支 |
| 19 | `gradle :app:assembleRelease` | `Release 构建` | 原命令，签名凭据从导出的环境变量读取 |
| 20 | Dex2C 加固（dcc） | `Dex2C 加固（dcc）` | `scripts/cnb/harden-dex2c.sh`，timeout **90m** |
| 21 | VMP 加固（壳） | `VMP 加固（壳）` | `scripts/cnb/harden-vmp.sh`，timeout **120m** |
| 22 | Verify v2/v3 signing | `v2/v3 签名校验` | `scripts/cnb/verify-apk-signing.sh` |
| 23 | Unit tests | `单元测试` | 原命令 |

## 平台差异的处理

**上下文变量**

| GitHub | CNB |
| --- | --- |
| `github.event_name` | `CNB_EVENT` |
| `github.event.pull_request.base.sha` | `CNB_PULL_REQUEST_TARGET_SHA`，再取 `git merge-base` 还原分叉点 |
| `GITHUB_WORKSPACE` | `CNB_BUILD_WORKSPACE`（`/workspace`） |
| `RUNNER_TEMP` | `/workspace/.ci-tmp/<step>` |
| `GITHUB_OUTPUT` | `##[set-output k=v]` + job `exports` |
| `secrets.KEYSTORE` 等 | 私密仓库 `SOMCP/key` 的 `android-signing.yml`，stage 级 `imports` |

**超时**：Job 级默认 2h、上限 12h，所以 Dex2C / VMP 显式写了 `timeout: 90m` / `120m`；
原生编译与 Blutter 这种长任务也一并显式声明，不靠默认值。

**`::error::` / `::warning::`**：CNB 没有注解语法。错误一律「原文案写 stderr + 非零退出码」，
警告写普通日志，语义（阻断 / 不阻断）不变。

**缓存**：`actions/cache` 用 key 失效，CNB 的节点缓存不按 key 失效。
直接照搬会出现「改了 `build-native-android.sh` 还复用旧归档」的静默错误，
所以 `scripts/cnb/native-cache-key.sh` 保留 hashFiles 那个 key 的**语义**：
输入（`build-native-android.sh`、`rizin-cross-*.ini`、`rizin-native.ini`、`app/src/main/cpp/CMakeLists.txt`）变了就清空产物目录，没变就保留。
`rizin-build/` 与 `third_party/lief-build/` 通过软链落到 `native-build` data 卷，
供同一流水线的后续 stage 复用；卷随流水线销毁，**不跨流水线复用**
（原工作流也一样：CI 缓存从不命中，`build-native-android.sh` 每次都全量编译）。

Gradle 缓存保持关闭语义：`/root/.gradle` 只是 data 卷，不设跨流水线缓存。

**任务间产物共享**：CNB 只跨 job 共享 `CNB_BUILD_WORKSPACE` 与文件顶层声明的 `volumes`，
所以 `native-build`（原生归档）与 `gradle-user-home`（挂到 `/root/.gradle`，Gradle 用户目录）
都用 `data` 类型卷声明。Gradle 用户目录直接挂到镜像 `ENV` 写死的位置，是为了让每个 stage
的 `gradle` 无需任何环境变量就指向同一份缓存 —— 环境变量不跨 stage 传递。

**Gradle 用户目录必须挂到镜像写死的位置**：环境变量不跨 stage 传递，每个 stage 的
`GRADLE_USER_HOME` 取的是镜像里 `ENV` 的值，不是上一 stage `export` 的值。
早先的版本把卷挂在 `/gradle-home`、却只在前置 stage 里 `export GRADLE_USER_HOME`，
结果每个 `gradle` stage 都用镜像里的空用户目录（`/root/.gradle`），`Android Lint` 直接报
`Plugin [id: 'org.jetbrains.kotlin.android', version: '2.4.0'] was not found`。
现在卷直接挂到 `/root/.gradle`，`scripts/cnb/setup-build-env.sh` 再把镜像内的用户目录内容
（`scripts/cnb/gradle-init.gradle` + 依赖预热结果）搬进卷，首次构建就有缓存可用。

预热为什么必要：`gradle/actions/setup-gradle` 在上游把插件和构建期依赖拉好，
CNB 上没有对应动作；不预热就只能每个 stage 从空缓存现场冲网。预热在镜像里做
（`image/cnb-tools.Dockerfile` 的 warmup 构建，插件版本与仓库声明都从仓库自己的
`build.gradle.kts` / `settings.gradle.kts` 里读，不另抄一份），只在镜像重建时付出一次成本；
卷随流水线销毁，所以预热结果不会跨流水线污染，`cache-disabled` 的语义不变。

**Maven Central 限流必须正面处理**：`repo1.maven.org` / `repo.maven.apache.org`
对同一出口 IP 有共享请求上限，实测连打同一个 POM 40 次有 16 次返回 429（40%）。
Gradle 对 429 **是**会重试的（`NetworkingIssueVerifier` 把它归入 transient），
但默认只试 3 次、退避 1 秒，冷启动那一波并发下不够。重试用尽后它报的仍是
`Plugin [id: ..., version: ...] was not found` —— 看起来像版本号写错。
注意 `org.gradle.internal.repository.max.retries` 这个键在 Gradle 8 里**不存在**
（正确键是 `max.tentatives`）。而且这组开关**必须带 `systemProp.` 前缀**：
源码是 `Integer.getInteger(KEY)` 读 **JVM 属性**，Gradle 只把 `systemProp.*` 转发进 JVM。
不带前缀看上去更像「Gradle 属性」，实际根本不读 —— A/B 实测（空用户目录、最小工程）：
不带前缀 `max.tentatives=3` → `BUILD FAILED`；带前缀 `=12` → `BUILD SUCCESSFUL`。
这两者只解决零星 429，解析源本身不可达时照样失败，所以主力仍是镜像预热。

主力的做法是 `scripts/cnb/gradle-init.gradle`：把镜像**追加**在原仓库列表之后。
它只在 `CNB_BUILD_ID` 存在时生效，本地开发完全不介入。
兜底有三层，判据都不放松：

1. `gradle.properties` 的 `systemProp.org.gradle.internal.repository.max.tentatives=12` +
   `initial.backoff=1000` —— 把重试次数从默认 3 次提到 12 次。
2. `scripts/cnb/gradle.sh` 外层重试：失败 → 退避 → 原命令重跑，最多 3 次。
   已下载的依赖不会重下，重跑只重新解析；真失败重跑仍然失败。
3. `gradle-proxy.init.gradle.kts` 在 `settingsEvaluated` 里**断言**上面两个属性存在：
   缺了直接报出修复方法，而不是让 429 再伪装成「插件不存在」。

另外 `gradle-proxy.init.gradle.kts` 还会把 `MavenRepo` 挪到 pluginManagement 首位
（`remove` + `addFirst` 同一实例；Gradle 8 没有 `RepositoryHandler.move`，
`clear()` 重建会连镜像一起清掉）。原因：`google()` 排在 Central 前面，而 Google Maven
没有 `kotlin.android.gradle.plugin` 这类标记 artifact，每个插件都要先吃一次 404 才回落。
这轮 404 与真正要拉的 POM 一起把 429 打出来。只调顺序、不增删仓库，镜像仍在末尾兜底。

- **不删不改原仓库**：`google()`、`gradlePluginPortal()`、原 `mavenCentral()` 全在，
  解析顺序和失败语义不变；
- **版本与产物不变**：镜像里是同一份构件（`group:artifact:version` 一致，字节相同），
  实测 `gradle-9.2.1.jar` 与 `kotlin-gradle-plugin-2.4.0-gradle813.jar` 都按声明解析到位；
- **判据不变**：Gradle 只在 404 时才试下一个仓库，真不存在的版本照样失败。

实测对比（同一台机器、空用户目录、冷启动）：不挂镜像 4 次里 1 次成功，
挂上镜像 4 次全成功。

### 插件解析与依赖解析不能用同一个镜像

这条是踩出来的，写在这里免得下次「统一一下」：

`maven.aliyun.com/repository/public`（Maven Central 镜像）对**不存在的构件**不返回
404，而是 `200` + 一张「该资源不存在」的 HTML 页。Gradle 只看状态码，见到 200 就
认定该仓库命中、不再往下试，于是 Google 上真实存在的 marker 永远取不到：

```
Plugin [id: 'com.android.application', version: '9.2.1', apply: false] was not found
  Searched in the following repositories:
    cnb-mirror-0(https://maven.aliyun.com/repository/public)
    Google
    MavenRepo
    Gradle Central Plugin Repository
```

「搜过 Google 还是没有」是假象 —— 它没走到 Google。AGP 9 从未发布到 Maven Central，
`com.android.application` 的 marker 只在 Google 仓库里，所以在插件仓库列表里插一个
Maven Central 镜像，等于把它遮死。

现在的分工（两边都仍走 `all {}` 追加，见上一节）：

| 用途 | 追加的镜像 | 说明 |
| --- | --- | --- |
| 依赖解析 `dependencyResolutionManagement` | `.../repository/public` | Maven Central 镜像，Kotlin / AndroidX 等普通依赖在这 |
| 插件解析 `pluginManagement` | `.../repository/google` | 代理 `dl.google.com/dl/android/maven2`，命中的是同一份构件 |

插件侧不挂 Maven Central 镜像：Kotlin 插件 marker 本身在 Maven Central 也在
Gradle Plugin Portal，原仓库列表够用，不需要镜像。

## 无法逐字等价的项

1. **`Install native build tools` 不再执行 `apt-get install`。**
   CNB 的任务容器以非 root 运行，且每次运行都从同一镜像起，
   所以在 `image/cnb-tools.Dockerfile` 里把 `meson` / `ninja-build` / `gcc` / `g++` / `pkg-config`
   （外加 LIEF 段需要的 `cmake`）一次性装好，运行期改为断言这些工具存在且版本可读。
   判据等价（缺工具时仍然失败），失败点更靠前、报错更明确。

2. **`sdkmanager` 的安装动作前移到镜像。** VMP 步骤里的
   `sdkmanager "platforms;android-34" "cmake;3.22.1"` 仍然保留调用，但已是幂等空操作。

3. **`workflow_dispatch` 的替代入口是 `web_trigger.test-v10`。**
   CNB 的手动触发走页面「自定义手动触发」（或在 `web_trigger.yml` 里配按钮），
   不存在与 `workflow_dispatch` 一一对应的 API 名字。

4. **`PR size check` 的 `::warning::` 不再是注解**，只是普通日志行；
   由于原步骤退出码恒 0，阻断语义完全一致。

5. **不存在 `actions/checkout` 的 `fetch-depth` 参数**：CNB 代码准备阶段拉取完整历史，
   效果等同 `fetch-depth: 0`，但没有任何开关可以表达「浅克隆」。

## 镜像补齐的宿主环境差异

GitHub 的 `ubuntu-latest` 自带一批裸镜像没有的工具，缺了它们报错点会离根因很远，
因此 `image/cnb-tools.Dockerfile` 显式补齐，并在 `setup-build-env.sh` 里断言：

- `python`（`python-is-python3`）：`app/src/main/cpp/CMakeLists.txt` 用 `COMMAND python` 调
  `app/generate_header.py`。缺它时 CMake 在 key-gen 处 `FATAL_ERROR`，而这一步发生在
  原生编译（约 30 分钟）之后，症状是 Release 构建失败、Dex2C 找不到 APK。
- `meson` / `ninja-build` / `cmake` / `gcc` / `g++` / `pkg-config`：原工作流用 `apt-get` 装，
  这里前移到镜像（任务容器非 root）。
- GNU 版 `find` / 常规 `coreutils`：`native-cache-key.sh` 的清理依赖 `-mindepth`。

## 需要维护者补齐的密钥

`SOMCP/key` 私密仓库里需要新增 `android-signing.yml`
（密钥仓库只能在 Web 界面编辑，NPC 的 `CNB_TOKEN` 默认只能访问当前仓库，写不进去）：

```yaml
allow_slugs:
  - SOMCP/SOMCP
allow_events:
  - push
  - pull_request
  - web_trigger.*
KEYSTORE: "<release JKS 的 base64 内容，单行>"
PASSWORD: "<storePassword>"
ALIAS: "<keyAlias>"
ALIAS_PASSWORD: "<keyPassword>"
```

四个变量与 GitHub 侧仓库 secrets 同名同义，`KEYSTORE` 同样是 BASE64 编码的 JKS。

`allow_events` 必须包含 `pull_request`：它属于 CNB 的「不可信事件」，
不声明 `allow_events` 时密钥文件无法被 PR 流水线引用，PR 上就永远只能走 CI-only 临时 keystore。

补齐前流水线**不会失败**：`prepare-keystore.sh` 在四个变量任一缺失时生成一次性的
CI-only keystore（`keytool -genkeypair`，每次运行随机），并用它签 release APK。
这种 APK 不能覆盖安装真实发布包，只用于构建验证，与 GitHub 侧
`Restore release signing keystore (or CI fallback)` 的 fallback 分支行为一致。

另外两个可选变量（原 `release.yml` 用到，`test-v10.yml` 没有）：`TM`（签名 pin 的 XOR 密钥）
与 `LRP_API_KEY`。缺失时 CMake 会用每次构建随机生成的 `TM`，`LRP_API_KEY` 缺失只是上报不带 key，
都不影响本流水线的判据。

## 已知风险

- **流水线首次运行必然慢**：镜像首次构建要装 Android SDK（含 NDK 29，约 1.5 GB），
  之后 `docker:cache` 会复用。原生后端本身即 4 ABI × (Rizin + LIEF) 全量编译。
- **Dex2C / VMP 依赖第三方联网**：dcc、Apktool、XopProtector 都从 GitHub 拉取，
  版本已 pin 到 commit / tag，网络故障时该 stage 会失败（原工作流同样如此）。
- **`app/src/main/jniLibs/*.so` 由 gradle 任务编译生成**（`buildUnidbgNative`），
  仓库本身不提交这些产物；因此本流水线在 CNB 上产出的 APK 同样依赖
  `third_party/*` submodule 齐全，缺 submodule 会在 `校验代码准备` 直接失败。

## 镜像构建上下文

`docker:cache` 的 `docker build` 上下文**只包含 Dockerfile 和 `by` 声明的文件**，
不是整个仓库。所以 Dockerfile 里 `COPY` 到或读到的每个仓库文件都必须在 `by` 里出现，
漏一个的报错形态是：

```
failed to calculate checksum of ref ...: "/scripts/cnb/gradle-init.gradle": not found
```

看着像路径写错，实际是文件没进上下文——这种情况下 Dockerfile 里不管写什么路径都找不到。

当前 `by` 包含：

- `image/cnb-tools.Dockerfile` —— Dockerfile 自身
- `scripts/cnb/gradle-init.gradle` —— `COPY` 进 `/opt/gradle-user-home/init.d/`
  与 `/opt/cnb/`（预热期显式 `--init-script` 用）
- `scripts/cnb/gradle-proxy.init.gradle.kts` —— 预热期的代理桥接，与运行期
  `scripts/cnb/gradle.sh` 传的是同一个文件
- `scripts/cnb/gradle-cache-only.gradle` —— 「只看缓存」复核用的 Groovy init
  script，`COPY` 到 `$GRADLE_USER_HOME/cnb-cache-only.gradle`，由上面那份
  Kotlin init script 在 `-PcnbCacheOnlyCheck` 时 `apply(from:)`
- `scripts/cnb/warmup-project.sh` —— 把下面几个文件改写成最小工程
- `build.gradle.kts` / `settings.gradle.kts` / `gradle.properties` —— 预热工程从里面读
  插件版本、仓库声明与重试参数
- `buildSrc/` —— **不在 `by` 里**。预热工程既不能有 `buildSrc/`（Gradle 看见它就会
  先编译一遍，插件还没下就先要求它可用），也不能留下 `:app` 里那行
  `id("somcp.patched-local-jars")`（找不到实现，整个 app 脚本编译不过，而它的
  `dependencies {}` 全写在 `plugins {}` 之后）。两件事都由
  `scripts/cnb/warmup-project.sh` 处理，容器里不需要看见这个目录
- `app/build.gradle.kts` 与 `app/libs/` —— 预热**第一遍按仓库原样跑**，`:app` 的真实
  脚本要求值一次，才能把 androidx / compose / ktor / okhttp 与
  `files("libs/*-patched.jar")` 解析掉。第二遍才换成生成的
  `plugins {}` + 最小 `android {}`，那时它们已不影响结果。早先版本怕「脚本编译不过
  就闷杀整层预热」而干脆不带 `:app` 脚本，代价是 `:app` 的运行时依赖一个都没预热，
  运行期照样现场冲网

在 `by` 里声明只解决「进上下文」，不解决「进镜像」：Dockerfile 里必须再 `COPY`
一次，否则 `RUN` 阶段根本看不到它们（曾因此失败在
`sed: can't read /build.gradle.kts: No such file or directory`）。
`COPY` 的源是上下文根、按仓库相对路径写，不能带 `../`；目标用绝对路径，
不依赖当时的工作目录。这些文件被拷到 `/tmp/cnb-warmup/`（`app/build.gradle.kts`
落到 `/tmp/cnb-warmup/app/`）后，由 `scripts/cnb/warmup-project.sh` 就地改写成最小工程：

- `build.gradle.kts` 只留 `plugins {}`；
- `settings.gradle.kts` 只留 `pluginManagement { repositories { ... } }`，
  再把仓库自己的 `dependencyResolutionManagement { ... }` **原样**接在后面
  —— 插件 buildscript classpath 的解析走后者，缺了它只剩隐式 `MavenRepo`；
  末尾再加 `include(":app")`，让预热把子项目也配置起来；
  这一段必须照抄而不是手写一份 `google() + mavenCentral()`：本仓库还依赖 JitPack 的
  `com.github.<owner>:<repo>` 坐标，手写的列表里没有 `jitpack.io`，预热会在
  `:app:dependencies` 处把它解析成 `FAILED`（实测日志里是
  `com.github.rikkahub:markdown:d79a97cc8e FAILED`，`jitpack.io` 一次都没被请求），
  而运行期是有的 —— 两份仓库列表不一致，等于给运行期留了一份没预热到的依赖；
  **仓库声明必须保留**——早先的做法是清空成一行 `rootProject.name`，Gradle 于是
  只剩缺省的 `gradlePluginPortal`，而 AGP 的 marker 在 Google，预热解析
  `com.android.application:9.2.1` 永远拿不到；运行期则相反，只剩 Google/MavenCentral、
  缺 aliyun 镜像（`gradle-init.gradle` 追加的那条）。两边任何一种都会表现为
  `Plugin ... was not found`，所以改写脚本用 `grep` 断言「插件块在」+「仓库声明在」，
  取不到就失败，不生成残缺工程；
- 预热跑的是 `help :app:dependencies --configuration releaseRuntimeClasspath`，
  不只是 `help`。`help` 只做配置阶段，`:app` 的运行时依赖（androidx / compose /
  ktor / okhttp…）一个都不会被解析，于是预热「成功」得只做了一半，运行期照样
  现场冲网。实测同一份用户目录：只跑 `help` 时 `androidx` 目录根本不存在，
  加上这条之后 `androidx.core` / `androidx.compose.ui` / `io.ktor` /
  `com.squareup.okhttp3` 都在，用户目录从 612 MB 到 619 MB —— 代价很小。
- 预热命令与运行期同一条路：`CNB_BUILD_ID`（`gradle-init.gradle` 走同一分支）+
  两个 init script + 同一个 shim。区别只有三点：不给 `--offline`（预热的活就是联网），
  加 `--no-configuration-cache`（`gradle.properties` 里开着它，而预热工程每次只有一次
  执行机会，存下来的配置缓存毫无收益，却在这类一次性工程上多一个失败点），
  以及 `GRADLE_USER_HOME` 显式指到 `/tmp/cnb-warmup-home` 再 `cp -a` 回
  `/opt/gradle-user-home`——镜像 `ENV` 里是 `/root/.gradle`，不显式给的话预热结果
  会被收尾的 `rm -rf /root/.gradle` 一起删掉，等于白预热。

预热整段加了 `timeout 900`：CI 的代理变量在无网环境下会变成「连上去不说话」的
黑洞，而 Gradle 的仓库超时是无限的，一次挂起就足以让镜像构建被平台杀掉。
（只跑 `help` 时 600 秒够用；多解析一张完整的运行时依赖图后放宽到 15 分钟。）

还有一条容易踩的：**`RUN` 的续行里不能夹注释**。行尾 `\` 会把下一行的 `# 注释`
拼进同一条命令，而 `#` 只在行首才是注释，于是被拼到 `sed -n '...'` 后面就成了
文件参数：

```
sed: can't read /build.gradle.kts: No such file or directory
```

报错看着像路径问题，其实是上一行的注释被当成了参数。预热段的所有注解都写在
`RUN` 之前，命令体内保持纯净。

`versionBy` 必须与 `by` 逐项对齐：`docker:cache` 的缓存键就是 `versionBy` 的文件内容，
只写 Dockerfile 时改预热脚本不会让缓存失效，流水线继续复用那张「预热从未成功过」
的旧镜像，然后在运行期复核里报 `warmup cache is incomplete` —— 改了半天脚本，
跑的还是老镜像。

第二个坑在调用方式上：**预热脚本必须用 `bash` 跑，不能用 `sh`**。`scripts/cnb/*.sh`
一律是 `#!/usr/bin/env bash` 且开头 `set -euo pipefail`，而 Docker 的 `RUN` 默认
shell 是 `/bin/sh` → dash，不认 `pipefail`：

```
/opt/cnb/warmup-project.sh: 21: set: Illegal option -o pipefail
ERROR: process "/bin/sh -c ..." did not complete successfully: exit code: 2
```

这行 `sh -x .../warmup-project.sh` 当时写在 `if` 之外，所以连「预热失败只打
warning、镜像照常产出」的兜底都进不去 —— 一段本该降级的逻辑把整层构建判死。
运行期那边一直是 `bash scripts/cnb/...`，两边入口不一致才留下这个洞。现在改成
`bash -x`，与脚本 shebang、与 `.cnb.yml` 里所有 stage 的调用方式对齐。

### `buildSrc` 的 `kotlin-dsl` 必须钉版本、自带插件仓库

`buildSrc/` 在 Gradle 里是个 included build：只要 settings 所在目录有它，Gradle 就会在
**配置任何工程之前**先把它编译一遍。它既不继承 `settings.gradle.kts` 的
`pluginManagement` / `dependencyResolutionManagement`（`RepositoriesMode.FAIL_ON_PROJECT_REPOS`
管不到它），`--init-script` 传来的仓库对它的 `pluginManagement` 也不生效 ——
它只认自己脚本里写的那几行。

于是两件事都得在 `buildSrc/build.gradle.kts` 里写清楚：

1. **钉住版本**：`id("org.gradle.kotlin.kotlin-dsl") version "6.6.4"`。不写版本时
   `kotlin-dsl` 的 marker 版本是 `gradle-kotlin-dsl-<Gradle 版本>-<时间戳>` 形状，
   缓存里存下的键与下一次请求的键可能对不上。
2. **自带 `gradlePluginPortal()`**：它是该 marker 唯一的来源。缺了就是
   `Plugin [id: 'org.gradle.kotlin.kotlin-dsl', version: '6.6.4'] was not found`。
   这几行的顺序与 `settings.gradle.kts` 一致（镜像由 init script 插在最前）；
   `--init-script` 传来的仓库对 included build 的 `pluginManagement` 不生效，
   所以这份列表是 marker 唯一的来源，不能指望别处补齐。

报错读起来是这样的（`cnb-fhv-1k621k7qm` / `cnb-e4f-1k62256dl`）：

```
* Where:
Build file '/workspace/buildSrc/build.gradle.kts' line: 15
Plugin [id: 'org.gradle.kotlin.kotlin-dsl', version: '6.6.4'] was not found in any of the following sources:
- Searched in the following repositories:
    Gradle Central Plugin Repository
```

`Searched in` 里只有 Gradle Central Plugin Repository —— 那是 `kotlin-dsl` 插件自己
的缺省仓库，不是脚本里写的 `gradlePluginPortal()`。看到这一行就说明那一刻连
`buildSrc` 脚本都还没读完，问题在「插件从哪来」，不在依赖图。

**预热工程里则必须没有 `buildSrc/`**：预热的目的就是把插件下进用户目录，
预热工程里没有源码也没有 `libs/`，编译 `buildSrc` 毫无意义，只会把「插件还没下」
变成「插件必须先可用」。`warmup-project.sh` 一进目录就删，Dockerfile 里还有一条
`rm -rf` 兜底。删的都是 `/tmp/cnb-warmup` 里的副本，仓库自己的 `buildSrc/`
一个字节不碰。

删掉目录只断了一半。`buildSrc` 里那几个**只躺在 `src/` 里、不在 `plugins {}` 里
带版本声明**的插件（本仓库的 `somcp.patched-local-jars`）还有另一半：

| 预热工程里的状态 | 结果 |
| --- | --- |
| 有 `buildSrc/`，`:app` 没声明那个 id | `Plugin [id: '...'] was not found ... (plugin dependency must include a version number for this source)` |
| 没 `buildSrc/`，`:app` 仍声明那个 id | 同一句报错，落在 `app/build.gradle.kts` 的 `plugins {}` 上（`cnb-hkj-1k624u580`） |

第二种比第一种更贵：`plugins {}` 就有这一行，脚本编译失败之后 `dependencies {}`
一行都求值不到（`val releaseKeystoreProperties` 就在 `plugins {}` 后面），
androidx / compose / ktor / okhttp 全没进缓存，而日志只看得到一句插件找不到。

所以 `warmup-project.sh` 的 `disable_buildsrc_plugin()` 把两边一起断：删目录 +
把那行 `id("somcp.patched-local-jars")` **行尾注释掉**（`// [cnb-warmup] disabled: …`，
行首、缩进、行号一律不动），随后 grep 断言行首已经不是 `id(...)`；改了仓库写法让
sed 失配时报错退出，不静默放行。这个插件干的是「用 `app/libs` 下的 jar 顶掉上游
同坐标模块」，而预热工程里那些上游坐标本来就不出现，去掉它不影响依赖图的完整性。

## 预热分两遍：第一遍按仓库原样跑

只跑一遍「最小工程」有个隐藏代价：`:app` 的脚本被砍到只剩 `plugins {}` 之后，
`dependencies {}` 里那些 androidx / compose / ktor / okhttp **一条都不会进缓存**，
运行期照样现场冲网 —— 预热等于只做了一半。而直接照抄真实脚本又不行：脚本里任何
一句编译不过的写法（历史例子：`implementation(module("g:a:v"))`，
`Dependencies.module` 只收三个参数）都会让整层预热以 `BUILD FAILED` 收场，
报错点还跟依赖图毫无关系。

所以拆成两遍（`scripts/cnb/warmup-project.sh`）：

1. **第一遍，仓库原样**（联网）：`app/build.gradle.kts` 在、`app/libs/` 在
   （只把 `buildSrc` 那个插件的 id 注释掉，见上一节）。这一遍把插件 marker、AGP、
   lint 以及 `:app` 的整张运行时依赖图下进 `GRADLE_USER_HOME`。**失败即整层失败**
   —— 缓存没建起来就不该出镜像。
2. **第二遍，最小工程**（联网）：`:app` 换成生成的最小脚本、
   `settings` 只留 `pluginManagement` + 照抄的 `dependencyResolutionManagement`。
   这一遍失败**只打 WARNING**：依赖在第一遍已经下来了，缺的只是改写后那份工程的边角。

镜像层的 `RUN` 只管两件事：跑这个脚本，然后用 `--offline` + `-PcnbCacheOnlyCheck`
做一次「只看缓存」的复核。

第二遍里 `settings.gradle.kts` 那条 `somcpPatchedLocalJars` 仓库仍然照抄保留（它指向的
目录此时已不存在，Gradle 视为「什么都找不到」），依赖图照样解析。

### 裁根脚本时要把 `extra["somcp*"]` 留下

`rewrite_root_script` 把根 `build.gradle.kts` 剪到只剩 `plugins {}` —— 但**第一遍跑的是
真实的 `app/build.gradle.kts`**，它第 40 行就写着 `rootProject.extra["somcpNamespace"] as String`。
三行 `extra[...]` 一起被剪掉之后：

```
* Where:
Build file '/tmp/cnb-warmup/app/build.gradle.kts' line: 40
* What went wrong:
Cannot get property 'somcpNamespace' on extra properties extension as it does not exist
```

报错点落在 app 脚本里，看起来像「app 脚本自己有问题」，实际是预热把上游的常量删了。
所以 `rewrite_root_script` 在 `plugins {}` 之后无条件重贴 `^[[:space:]]*extra\["somcp` 三行，
并逐个断言它们在改写结果里 —— 这几行是纯字面量赋值、不引用任何插件，留在预热工程里没有副作用。

**同一个函数里还有两处坑，一起记下**（`cnb-4gb-1k625dvfg` 连着红了两次，都是它）：

- 中间文件不能叫 `build.gradle.kts.new`。Kotlin DSL 按扩展名认脚本，`.kts.new` 只是普通文件，
  Gradle 不会读；`mv` 回原名之后看似「改完了」，实际上一行都没进构建（报错仍是上面那句
  `Cannot get property 'somcpNamespace' ...`，位置也一样，完全看不出改写没生效）。改用
  `root-plugins-block.kts` 这种**自身也是合法脚本名**的临时文件。
- `extra` 那几行必须在覆盖根脚本**之前**取出来。先覆盖再 grep 同一个文件，得到的是
  `grep: build.gradle.kts: input file is also the output`，一行都拿不到，断言当场判失败。

## 预热失败与工具链失败的分界

镜像里的预热段（`warmup-project.sh` + `--offline` 复核）与工具链（JDK / Gradle /
SDK / NDK）在同一个 Dockerfile 里，但预热在**独立的 RUN 层**：前面几层照样命中
`docker:cache`，预热重来一次只是几十秒到几分钟，不是「整个镜像重来」。两层判据：

- **镜像层**：预热失败**即整层失败**（把网络层证据与 Gradle 日志尾部打到 stderr，
  否则只剩一行 `BUILD FAILED`）。这是有意改的：早期版本「warning + 退出码归零」，
  留下一个带残缺缓存的镜像，被 `docker:cache` 按版本名记住，之后每次流水线都栽在
  同一个 `Plugin ... was not found` 上，除了清缓存重建镜像没有别的解法。
  一次网络抖动赔一次重建，比每次流水线都红划算。
- **运行期**：`scripts/cnb/setup-build-env.sh` 在第一个 stage 用
  `bash scripts/cnb/gradle.sh --offline -q -PcnbCacheOnlyCheck help` 复核 ——
  走的是与后续每个 stage 完全相同的入口（同一个 proxy init script、同一份用户目录）；
  `-PcnbCacheOnlyCheck` 由 `scripts/cnb/gradle-cache-only.gradle` 把插件仓库与
  依赖仓库都换成空的本地文件仓库，于是「能不能解析到」只取决于
  `$GRADLE_USER_HOME` 里有没有，跟网络无关。跑不通当场失败，并指回 Dockerfile
  的预热段。这里曾经是裸 `gradle --offline`：既不带 proxy init script
  （预热带代理、复核不带，两边不是同一个判据），也不是 `export` 出来的
  `GRADLE_USER_HOME`，复核读的其实是另一个目录。

**为什么光有 `--offline` 不够**：`--offline` 只禁止联网，Gradle 仍然按仓库名去
`caches/modules-2` 里查索引，远端连不上时报的也是
`Plugin [id: ...] was not found in any of the following sources: Google, cnb-plugin-mirror-0(...)`，
和「预热没做完」一字不差。2026-10 就踩过这个坑：镜像重建（`versionBy` 只跟
Dockerfile 走，Dockerfile 一改 `docker:cache` 的 key 就变，overlay 从零开始）
之后第一次运行，预热确实做过，复核却因为当时到 Google / Maven Central 的链路
不可用而判红。换成空文件仓库后这层歧义消失：缓存里有就过，没有就是真没有。

这样「缓存可用」这个判据一条没少，只是失败点从镜像构建挪到了第一个 stage，
报错文字也从后面的 `Plugin [id: ..., version: ...] was not found` 提前成一句
「warmup cache is incomplete」。要多付一次 `gradle help` 的 10 秒左右（离线、无 daemon）。

已知的预热失败形态与当前处理：

| 现象 | 归属 | 处理 |
| --- | --- | --- |
| `sed: can't read /build.gradle.kts` | 上下文缺文件 / 续行夹注释 | 见上两节，已修 |
| `set: Illegal option -o pipefail` | 用 `sh`（dash）跑 bash 脚本 | 预热段改 `bash -x`，已修 |
| `Plugin [id: '...', version: '...'] was not found`，`Searched in` 里没有 Google | Maven Central 429 限流 | `gradle-init.gradle` 追加镜像；仍被限流时由运行期复核报错 |
| `Plugin [id: 'somcp.patched-local-jars'] was not found ... (plugin dependency must include a version number for this source)`，落在 `app/build.gradle.kts` 的 `plugins {}` 上（`cnb-hkj-1k624u580`） | 预热工程删了 `buildSrc/` 却留下 `:app` 那行 `id(...)`，整段脚本编译不过 | `warmup-project.sh` 的 `disable_buildsrc_plugin()` 把该行行尾注释掉（不动缩进与行号）并 grep 断言，已修 |
| `Plugin [id: 'com.android.application' ...] was not found`，`Searched in` 里 `cnb-mirror-*` 排在 Google 前 | Maven 镜像的 200 空壳挡住 AGP marker | 插件侧改挂 `repository/gradle-plugin`（对 AGP marker 返 404），见「插件解析与依赖解析不能用同一个镜像」 |
| `Plugin [id: 'org.jetbrains.kotlin.plugin.compose' ...] was not found`，`Searched in` 里有 google 镜像 | `repository/google` 里没有 Kotlin 插件 marker | 同上 |
| 镜像层预热 warning 里出现 `fus-statistics-gradle-plugin:2.4.0` 的 429 | 预热工程缺 `dependencyResolutionManagement`，插件 buildscript classpath 只剩隐式 `MavenRepo` | `scripts/cnb/warmup-project.sh` 补上该段，已修 |
| 预热与你都「成功」，但运行期仍在冲网（首次 `Android Lint` / `Debug 构建` 慢） | 预热只跑 `help`，`:app` 的运行时依赖从未被解析 | 预热改为 `help :app:dependencies --configuration releaseRuntimeClasspath`，并 `include(":app")` |
| 预热日志里 `com.github.<owner>:<repo> FAILED`，`jitpack.io` 一次都没被请求 | 预热工程的 `dependencyResolutionManagement` 是手写的，漏了 `maven("https://jitpack.io")` | `warmup-project.sh` 改为原样接上仓库自己的那一段 |
| 运行期复核报 `warmup cache is incomplete`，但 `Searched in` 里仓库地址指向外网 | 光靠 `--offline` 分不开「缓存空」和「网不通」 | 复核改用 `-PcnbCacheOnlyCheck`，仓库列表换成空文件仓库（`Searched in` 只剩 `cnb-cache-only`），已修 |
| 预热全绿但运行期 `--offline` 复核失败 | 预热用的 `GRADLE_USER_HOME` 与运行期不是同一个 / 预热缺 init script | 见上一节，已修 |
| 预热超时 / 镜像层被杀 | 网络 | 镜像照常产出，运行期复核给出明确失败 |

`GRADLE_WARMUP_CHECK=0` 可以关掉运行期复核（只用于排查，正常流水线不要关）。

## JitPack 的坐标会被 Maven Central 镜像接走

`Android Lint` 在 `:app:debugCompileClasspath` 上挂掉：

```
Could not resolve com.github.rikkahub:markdown:d79a97cc8e.
  > Could not GET 'https://repo.maven.apache.org/maven2/com/github/rikkahub/
     markdown/d79a97cc8e/markdown-d79a97cc8e.pom'.
     Received status code 429 from server: Too Many Requests
```

印在报错里的是 Maven Central，看着像限流，其实是**仓库列表被镜像接管了**。
四个源实测（同一时刻）：

| 源 | 结果 |
| --- | --- |
| `google()` | 未命中（这个坐标就不在 Google） |
| `repo.maven.apache.org` | 404 —— 该坐标本来就不在 Maven Central |
| `.../repository/public` | 404 / 429 / 200 空壳，换着来 |
| `jitpack.io` | 200，jar 的 sha1 与 `.module` 声明一致 |

`settings.gradle.kts` 里 `jitpack()` 排在最后，而 `gradle-init.gradle` 把 Maven
Central 镜像**追加在文件末尾** —— 于是 JitPack 的坐标先落到镜像上。镜像没被限流
就返回 `200` + 一张「资源不存在」的 HTML，被限流就是 `429`，两种都让 Gradle 原地
判死，**真正的 jitpack.io 永远走不到**。这与上面「插件侧不能用 Central 镜像」
是同一个假 200，只是这次撞在依赖解析上。

修法（`scripts/cnb/gradle-init.gradle`）：

- `noMirror`：给 JitPack（`jitpack.io`）和任何 `file:` 仓库（含复核用的空仓库）
  打标记，追加镜像是跳过它们；
- `addCentralOnlyMirror`：额外追加一个带着内容过滤的镜像，
  `excludeGroupByRegex('com.github.rikkahub.*')` —— JitPack 的坐标是
  `com.github.<owner>:<repo>` 与 `com.github.<owner>.<repo>:<artifact>`，
  这个形状 Maven Central 上永远不会出现，于是在镜像那里被放过，继续走 jitpack.io。

试过但**不用**的方案：按 group 级 `maven-metadata.xml` 判断「Central 上到底有没有
这个 group」。实测在 aliyun 上不可靠 —— `androidx`、`io.reactivex`、`com.squareup.okhttp3`、
`com.google.code.gson` 全部 404，`com*` 这种宽前缀会把 `com.github.rikkahub`
一起放进来，窄前缀又会把 Central 的冷门依赖挡在外面。所以只排已知的非 Central 坐标。

留个判据：**新增非 Maven Central 的仓库（JitPack 之外的）时，同时往
`CENTRAL_ONLY_EXCLUDES` 补一条前缀**，否则镜像会把它接走，而报错只会指着镜像。

## 复核的仓库列表必须与预热逐个对上

`gradle-cache-only.gradle` 早先的做法是把仓库列表 `clear()` 掉，塞进唯一一个叫
`cnb-cache-only` 的空仓库。这条路从一开始就不可能通过：Gradle 的模块缓存**按仓库
url 算 hash 分索引**，预热下在 Google / MavenRepo / JitPack / 两个 `cnb-mirror-*`
名下，复核却拿着一个谁都没预热过的空仓库去查，报出来必然是「每条都不命中」。
镜像重建后它看起来「对」，只是因为那时缓存本来就是空的。

现在改成**原位替换**：顺序与数量跟预热时一模一样，每个 url 换成本地空目录，
再在这个目录里写一个 Gradle 自己的仓库信息文件
（`<repoDir>/.gradle/repo-info.json`，内容 `{"url": "<原 url>", "type": "maven"}`），
让空仓库的缓存索引指回原来那个 url。于是命中与否只取决于「预热有没有下过这份构件」。

这个文件不是公开 API，所以做了兜底说明：万一将来 Gradle 不再读它，复核会退化成
「全部未命中」—— **偏严的失败**，不会误放行；届时按日志里 `Searched in` 的清单改。

空目录建在 `$GRADLE_USER_HOME` 下，不写死 `~/.gradle`：镜像里那两者恰好是同一个
路径（都是 `/root`），但预热用的是 `/tmp/cnb-warmup-home`，任务容器也不保证
`HOME` 等于它。写死只会把目录生成在别处。

## 复核脚本本身也要落到用户目录

预热段第一次跑通之后（`[warmup] gradle help OK`，27s），紧接着那次复核在 2 秒内
失败，报的却是「脚本缺失」：

```
cnbCacheOnlyCheck requested but /root/.gradle/cnb-cache-only.gradle is missing
```

镜像把它 COPY 到 `/opt/gradle-user-home`，预热跑在 `/tmp/cnb-warmup-home`、运行期跑
在 data 卷 `/root/.gradle` —— init script 读的是后两者，镜像里那份从来没有出现在它们
中间。位置不对，报错却指向「预热没做完」，很容易往错的方向查。

于是先补了两条「投放」的腿：预热段在开跑前把它复制进 `/tmp/cnb-warmup-home`，运行期
由 `gradle-init.gradle` 的 `deployCacheOnlyScript` 投放到 `$GRADLE_USER_HOME` 与
`user.home/.gradle`。这条路上又踩了第二次：`COPY` 的落点从
`/opt/gradle-user-home` 改成 `/opt/cnb` 之后，预热段那句 `cp` 就变成「从不存在的位置
拷」，整层以 1 退出；报错是 `no such file`，而真正的判据是「缓存全不全」。

所以现在的做法是**不留投放这一步**：

- 脚本只放一个位置，`COPY scripts/cnb/gradle-cache-only.gradle /opt/cnb/`；
- 预热与运行期都用 `-Dcnb.cacheOnlyScript=/opt/cnb/gradle-cache-only.gradle`
  显式指过去（预热的两条 `gradle` 命令本来就带着它）；
- `gradle-proxy.init.gradle.kts` 的查找顺序是 `-Dcnb.cacheOnlyScript` →
  `$GRADLE_USER_HOME` → `user.home/.gradle` → `/opt/cnb`，找不到时把试过的路径
  全打出来；运行期由 `gradle-init.gradle` 顺带投放一份到用户目录，失败只打 warning
  （判据不依赖它）。

**init script 里没法自省「我在哪个用户目录」** —— system property 是在 init script
求值之后才应用的，此刻读到的还是启动时的旧值，所以路径只能靠显式参数给。

## 上游 unidbg jar 与 patched jar 的重名冲突

`Debug 构建` 第一次真正跑起来时，两处红点同一个根因：

```
Execution failed for task ':app:checkDebugDuplicateClasses'.
> Duplicate class com.github.unidbg.AbstractEmulator found in modules
    unidbg-api-0.9.9-android-patched.jar and com.github.zhkl0228.unidbg:unidbg-api:0.9.9
Execution failed for task ':app:mergeDebugJavaResource'.
> 2 files found with path 'android/sdk23/system/usr/share/zoneinfo/tzdata' from inputs:
    - unidbg-android-0.9.9-android-patched.jar
    - com.github.zhkl0228.unidbg:unidbg-android:0.9.9
```

`app/libs/*-patched.jar` 是上游同名模块的重打包版本，上游那份还在 classpath 上就必然撞。
**为什么 GitHub 上一直是绿的**：`files()` 的依赖不带坐标，Gradle 只在拿不到 POM 时才把
上游依赖当成「无元数据模块」，那种模块不参与冲突检测、两边并存也能编译过。CNB 的镜像
预热把 POM 缓存下来，真实依赖图第一次完整出现 —— 这是被预热照出来的存量 bug。

### 走过的一条弯路：把 jar 发布成本地 Maven 仓库

试过一版：`buildSrc` 把 `app/libs/*-patched.jar` 复制成带 `.module` 元数据的同版本模块，
`settings.gradle.kts` 里那个本地仓库排在最前，让 Gradle 的冲突解析挑掉上游那份。
依赖图确实干净了，但它把 buildSrc 变成了预热判据的一部分：

```
* Where: Build file '/workspace/buildSrc/build.gradle.kts' line: 23
Plugin [id: 'org.gradle.kotlin.kotlin-dsl', version: '6.6.4'] was not found
Searched in the following repositories: Gradle Central Plugin Repository
```

buildSrc 是 **included build**：不继承 `settings.gradle.kts` 的 `pluginManagement`，
`--init-script` 传进去的仓库对它也不生效，只能靠自己那份列表。而 `--offline` 复核读的是
镜像预热出来的用户目录 —— 预热工程里没有 buildSrc，`kotlin-dsl` 的 marker 从没进过缓存。
钉版本、自带 `gradlePluginPortal()` 都试过，仍然倒在同一行。

### 现在的做法

判据从「让冲突解析替我们选」改成「上游那份根本不进图」：
`buildSrc/src/main/groovy/somcp.patched-local-jars.gradle`（预编译脚本插件，Gradle 自带的
`groovy-gradle-plugin`，零外部插件依赖）在 `configuration.incoming.beforeResolve { }` 里
把上游坐标从待解析的 selector 集合里 `removeAll` 掉。上游那份因此**根本不会被解析**，
也就不会被任何消费者合并进 classpath，重复类无从发生。

判据是「这个配置里有没有同名 patched jar」（看 `allDependencies` 的构件名，不触发解析），
与「谁把上游 jar 带进来的」无关 —— 逐个 `exclude` 堵来路已经试过一次：带上游 jar 进来的
路径不止一条，排掉一条，换条路径又漏回来。

**为什么不是「解析完再删」** —— 这条坑踩了三回，全死在 configuration cache 上，
`gradle.properties` 里 `org.gradle.configuration-cache=true`，所以别再试。核心区别只有
一句：**解析结果只能在解析前用「待解析的 selector」表达，不能反过来在解析后用「已解析
的产物」去删** —— 后者一定会在存缓存那一步被重新求值。

1. `incoming.afterResolve { resolvedArtifacts }` + 从 `configuration.artifacts` 删：
   解析能过，但存缓存时会重放闭包、重新求值那个惰性属性，那时解析已结束
   （`cnb-d7c-1k623dl4d` 的 Android Lint）：

   ```
   Configuration cache state could not be cached: field `importDirs` of task
   `:app:compileDebugAidl` of type `com.android.build.gradle.tasks.AidlCompile`:
   error writing value of type
   'org.gradle.api.internal.artifacts.configurations.ResolutionBackedFileCollection'
   > Could not get unknown property 'resolvedArtifacts' for dependencies
     ':app:debugCompileClasspath'
   ```

2. 改成具名参数 `afterResolve { it.resolvedArtifacts }`：报错文字变了，病理没变，
   同一个地方照样红（`cnb-5qa-1k623v3ir`）。**闭包里读解析结果这件事本身**就不能放在
   `afterResolve` 里，换写法只是换报错。

3. `incoming.artifactView { beforeResolve { ... } }`：`ArtifactView.ViewConfiguration`
   上根本没有 `beforeResolve`（`cnb-o45-1k6242bj7`）：

   ```
   Could not find method beforeResolve() ... on object of type
   DefaultResolutionOutputs$DefaultArtifactViewConfiguration
   ```

   `beforeResolve` 长在 `ResolvableDependencies` 上，属于 configuration 层；
   artifact view 层只有 `componentFilter` / `lenient` / `withVariantReselection`，
   过滤出来的是「视图」，替不掉 `configuration.incoming.files` 本身。

`componentSelection.reject()` 也能达到同样效果（图解析阶段拒掉候选，同样不碰已解析
产物），但 `beforeResolve` 更直白：拿到的是 `ResolvableDependencies.dependencies`，
就是即将被解析的那张 selector 集合，`removeAll` 即可，顺手还能把被摘掉的坐标打进日志
（`[patched-jars] <configuration>: drop upstream <坐标>`）。

三条不变量写在插件头部注释里，改之前先读：

1. 只对 `unidbg-api` / `unidbg-android` 生效。`unicorn` / `capstone` / `keystone` 的上游
   jar 不是重复品而是**替代品**（`unicorn:1.0.15` 是 `unicorn.*` 唯一的来源），剔了会在
   `session_open` 时 `ClassNotFoundException`。
2. 同一配置里必须同时看到 patched jar 才动，否则说明该配置压根不需要它。
3. 副作用看得见：拒绝理由写进 `ComponentSelection.reject(...)`，`dependencyInsight` 里
   显示为 `rejected by rule` —— 依赖图被动过，日志里得看得见。

**buildSrc 的插件选择因此被限制住了**：只能用 `groovy-gradle-plugin`，不能用 `kotlin-dsl`。
后者要从 Portal 拿 marker，而 `--offline` 复核读的是预热出来的用户目录，那里没有它。
`scripts/cnb/setup-build-env.sh` 里那条复核的注释记着这件事。

**顺带补的一处**：镜像预热工程会生成一个一次性 keystore
（`release/keystore.properties` + `keytool -genkeypair`）。`:app` 的配置阶段要读
`signingConfigs.release`，文件缺失时 AGP 在配置期就报错 —— 那跟「依赖下没下全」无关，
却会让预热整段失败。运行期的真实签名仍由 `scripts/cnb/prepare-keystore.sh` 负责。
