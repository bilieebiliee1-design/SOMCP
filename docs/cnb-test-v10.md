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
Gradle 默认把 429 判成**不可重试**，于是一个限流响应被翻译成
`Plugin [id: ..., version: ...] was not found` —— 看起来像版本号写错。
`gradle.properties` 里的 `org.gradle.internal.repository.max.retries` /
`initial.backoff` 实测救不了（给 daemon JVM 设了属性也照样不重试 429），
所以不靠它，靠镜像。

真正有效的做法是 `scripts/cnb/gradle-init.gradle`：把镜像**追加**在原仓库列表之后。
它只在 `CNB_BUILD_ID` 存在时生效，本地开发完全不介入。

- **不删不改原仓库**：`google()`、`gradlePluginPortal()`、原 `mavenCentral()` 全在，
  所以 AGP 的 marker 仍走 Google，解析顺序和失败语义不变；
- **版本与产物不变**：镜像里是同一份构件（`group:artifact:version` 一致，字节相同），
  实测 `gradle-9.2.1.jar` 与 `kotlin-gradle-plugin-2.4.0-gradle813.jar` 都按声明解析到位；
- **判据不变**：Gradle 只在 404 时才试下一个仓库，真不存在的版本照样失败。

实测对比（同一台机器、空用户目录、冷启动）：不挂镜像 4 次里 1 次成功，
挂上镜像 4 次全成功。

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
- `build.gradle.kts` / `settings.gradle.kts` / `gradle.properties` —— 预热工程从里面读
  插件版本、仓库声明与 Maven 重试参数

这三个构建脚本在 Dockerfile 里必须用**相对路径**（`/build.gradle.kts`）读。
写 `/workspace/build.gradle.kts` 不行：`WORKDIR /workspace` 虽然在文件末尾，
但镜像里没有源码。

`versionBy` 仍只写 Dockerfile。被 `by` 额外带进上下文的文件只解决「可见性」，
不该让缓存版本跟着漂移；预热本身吃 `RUN` 层缓存，构建脚本变了 Gradle 会自己重解析。
