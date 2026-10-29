# SPDX-License-Identifier: AGPL-3.0-only
#
# SOMCP - image/cnb-tools.Dockerfile
# Copyright (C) 2026 SOMCP authors
# Upstream: https://github.com/bilieebiliee1-design/SOMCP
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License version 3 as published by
# the Free Software Foundation.
#
# 本文件不参与 APK 构建，只负责给 CNB 流水线准备基础工具链。
# 背景：CNB 没有 actions/setup-java、android-actions/setup-android 这类动作，
# 任务容器也不预装 JDK / Android SDK，因此把「Test v10」里由动作完成的部分
# （JDK 17、sdkmanager、构建期宿主机工具）固化成一个固定版本的镜像。
# Dockerfile 里的版本钉住是有意的：这些工具版本一旦漂移，原生后端产物就不可复现。
FROM eclipse-temurin:17-jdk-noble

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV ANDROID_HOME=/opt/android-sdk
ENV ANDROID_SDK_ROOT=/opt/android-sdk
ENV ANDROID_NDK_HOME=/opt/android-sdk/ndk/29.0.14206865
ENV GRADLE_USER_HOME=/root/.gradle
ENV PATH=/opt/android-sdk/cmdline-tools/latest/bin:/opt/android-sdk/platform-tools:/opt/gradle/bin:${PATH}

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bash ca-certificates curl git git-lfs jq unzip zip \
      python3 python3-pip python3-venv python-is-python3 \
      meson ninja-build cmake gcc g++ pkg-config make patch \
      autoconf automake libtool libarchive-tools openssh-client \
 && rm -rf /var/lib/apt/lists/*

# python3 + pip 是 meson（Rizin 交叉编译）与 dcc 的依赖。
# CMakeLists.txt 现在先 find_program 再调用（找不到就报清楚），所以不再依赖
# `python` 这个名字是否存在 —— 但仍然装 python-is-python3：镜像里跑的非
# CMake 脚本（dcc 的 shebang 是 /usr/bin/env python3，本地工具脚本有写
# python 的）在 GitHub runner 上一直拿到的是 `python`，保持同一套环境。

# Gradle 9.6.1：仓库故意不带 gradlew 启动器，版本必须由环境供给。
# 版本与 gradle/wrapper/gradle-wrapper.properties 一致。
ARG GRADLE_VERSION=9.6.1
RUN curl -fsSL --retry 3 -o /tmp/gradle.zip \
      "https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip" \
 && unzip -q /tmp/gradle.zip -d /opt \
 && ln -sfn "/opt/gradle-${GRADLE_VERSION}" /opt/gradle \
 && rm -f /tmp/gradle.zip \
 && gradle --version

# Android cmdline-tools + SDK 包。与 Test v10 的 sdkmanager 调用一一对应：
# platforms;android-36 / build-tools;36.0.0 / ndk;29.0.14206865，
# 外加 VMP 壳自身构建需要的 platforms;android-34 与 cmake;3.22.1
# （原工作流是在 VMP 步骤里现装，这里一次装好，缺包时不必联网）。
ARG CMDLINE_TOOLS_VERSION=13114758
RUN mkdir -p "${ANDROID_HOME}/cmdline-tools" \
 && curl -fsSL --retry 3 -o /tmp/cmdline-tools.zip \
      "https://dl.google.com/android/repository/commandlinetools-linux-${CMDLINE_TOOLS_VERSION}_latest.zip" \
 && unzip -q /tmp/cmdline-tools.zip -d "${ANDROID_HOME}/cmdline-tools" \
 && mv "${ANDROID_HOME}/cmdline-tools/cmdline-tools" "${ANDROID_HOME}/cmdline-tools/latest" \
 && rm -f /tmp/cmdline-tools.zip \
 && yes | sdkmanager --licenses > /dev/null \
 && sdkmanager --install \
      "platform-tools" \
      "platforms;android-36" "build-tools;36.0.0" "ndk;29.0.14206865" \
      "platforms;android-34" "cmake;3.22.1" \
 && sdkmanager --list_installed

# ---------------------------------------------------------------------------
# Gradle 用户目录预热
# ---------------------------------------------------------------------------
# gradle/actions/setup-gradle 帮上游做的事（配好源、把依赖拉好）在 CNB 上没有
# 对应动作，只能在镜像里预先做掉：
#   * scripts/cnb/gradle-init.gradle —— 用户级 init script，给仓库列表追加 Maven
#     Central 镜像（原仓库一个不动），解决 429 限流被误报成「plugin not found」；
#   * warmup 构建 —— 把插件 marker、AGP、lint 等构建期依赖一次下完。
#   * scripts/cnb/gradle-proxy.init.gradle.kts —— 内存里见代理变量就桥接成 JVM
#     代理属性（运行期由 scripts/cnb/gradle.sh 显式传 --init-script），预热也要。
# 运行期 /root/.gradle 是 data 卷，首次挂载为空，由 scripts/cnb/setup-build-env.sh
# 从 /opt/gradle-user-home 搬进去；镜像层保留原件，卷随流水线销毁。
COPY scripts/cnb/gradle-init.gradle /opt/gradle-user-home/init.d/cnb-init.gradle
COPY scripts/cnb/gradle-proxy.init.gradle.kts /opt/cnb/gradle-proxy.init.gradle.kts
COPY scripts/cnb/gradle-init.gradle /opt/cnb/gradle-init.gradle
# 「只看缓存」复核脚本：运行期 setup-build-env.sh 传 -PcnbCacheOnlyCheck 时由
# gradle-proxy.init.gradle.kts apply 它，预热期由下面那条 RUN 显式
# -Dcnb.cacheOnlyScript 指过去。
COPY scripts/cnb/gradle-cache-only.gradle /opt/cnb/gradle-cache-only.gradle

# 预热用的最小工程：插件版本与仓库声明都从仓库自己的构建脚本里读，不另抄一份
# （settings 里手写 google() / mavenCentral() 就等于绕开 settings.gradle.kts，
# 仓库换了源预热也不会跟着换）。
# build.gradle.kts / settings.gradle.kts / gradle.properties 由 .cnb.yml 的
# docker:cache.by 带进构建上下文（docker:cache 只复制 Dockerfile 与 by 声明的
# 文件），因此这三个文件必须显式 COPY 进来 —— 光在 `by` 里声明不会让它们
# 自动出现在镜像里。COPY 的源是上下文根、按仓库相对路径写，不能带 `../`。
#
# 改写的判据（下面那条 RUN 逐条对应）：
#   * **根 build.gradle.kts 只留 `plugins {}` 与 `extra["somcp*"]` 那几行** ——
#     其余内容（dependencies / configurations / 自定义 task / allprojects）在最小
#     工程里求值会失败，根里那几行 extra 是唯一的例外：第一遍跑的是真实的 app
#     脚本，它写着 `rootProject.extra["somcpNamespace"] as String`，剪掉就抛
#     `Cannot get property 'somcpNamespace' on extra properties extension`
#     （cnb-qno-1k625acuu）。app 那份第一遍按原样跑，第二遍才改写；改写的必要性
#     在于 `implementation(files("libs/*-patched.jar"))` 指向的文件不在构建上下文
#     （by 只带构建脚本），而 `module("g:a:v")` 这类写法在
#     Kotlin DSL 里连编译都过不了 —— 一旦脚本编译失败，整次预热以 BUILD FAILED
#     收场，镜像里一个依赖都没落下，改仓库源码里的写法也救不回来（那本就是
#     运行期的语法问题，不该由预热来判）。改写后由 warmup-project.sh 从原文件
#     读 namespace / compileSdk / minSdk 补一个最小 android {} 块给 :app；
#   * settings.gradle.kts 只留 `pluginManagement { repositories { ... } }` +
#     `dependencyResolutionManagement { repositories { ... } }` +
#     `rootProject.name` / `include` —— **仓库声明必须保留**：
#     早先的做法是把 settings 清空成一行 rootProject.name，Gradle 于是只剩
#     缺省的 gradlePluginPortal，而 AGP 的 marker 在 Google，预热解析
#     `com.android.application:9.2.1` 永远拿不到（镜像层只留 warning，
#     运行期的「只看缓存」复核随后报「warmup cache is incomplete」）；
#     模块脚本（app/build.gradle.kts）里另起的 `repositories {}` 也要合并进来，
#     并去掉 `repositoriesMode.set(FAIL_ON_PROJECT_REPOS)` —— 那条模式会拦住
#     合并进来的模块级仓库声明。只抄 settings 那一份时，模块声明的仓库一个都
#     不进预热工程，第二遍（唯一真解析依赖图的一遍）于是解析不全；
#   * 预热跑的不只是 `help`：`help` 只做配置，不解析 :app 的运行时依赖，androidx /
#     compose / ktor / okhttp 一个都进不了缓存，运行期照样现场冲网。多带一条
#     `:app:dependencies --configuration releaseRuntimeClasspath`，把 :app 真正用到的
#     那份依赖图解析一遍（实测同一份用户目录：只跑 help 时 androidx 目录不存在，
#     带上这条之后 androidx.core / androidx.compose.ui / io.ktor / okhttp 都在）。
#   * gradle.properties 必须一起进预热工程 —— 仓库级重试参数
#     （org.gradle.internal.repository.max.tentatives / initial.backoff）与
#     network.retries 都从这份属性文件读，而冷启动最吃重试的正是预热这一次解析；
#     少设一次就是「预热下的东西运行期用不上」，白跑。
# app/build.gradle.kts 与 app/libs/ 必须一起进上下文：预热的**第一遍**按仓库原样
# 跑，:app 的真实脚本要求值一次 —— 只有这样才能把 androidx / compose / ktor /
# okhttp 与 patched jar 的 x.y.z.1 解析掉（四个 jar 本体也从这里读，见
# warmup-project.sh 的 publish_patched_local_repo）。第二遍才换成 warmup-project.sh
# 生成的最小脚本（只含 plugins {} + 最小 android {}），那时它们已不影响结果。
# `app/libs/build/patched-jars-repo/` 那个空目录占位也一起进来 —— 它在仓库里就是为
# 了让 `files()` 声明时目录已在（Gradle 会把不存在的路径当成 fingerprint 失败）。
COPY build.gradle.kts settings.gradle.kts gradle.properties /tmp/cnb-warmup/
COPY app/build.gradle.kts /tmp/cnb-warmup/app/build.gradle.kts
COPY app/libs/ /tmp/cnb-warmup/app/libs/
# buildSrc 整个目录要进预热工程：预热第一遍按仓库原样跑（含真实 buildSrc），
# 第二遍才换成占位 —— 理由见下面「buildSrc 必须被预热」那段。
# 其中口径表 `somcpPatchedJars`（文件名 ↔ 上游坐标）另有用处：warmup-project.sh
# 按它把四个 `x.y.z.1` 铺成本地仓库，第一遍的真实 :app 才解析得到（插件在声明时把
# file 依赖换成坐标，没有这份仓库就是 `Could not find ...:0.9.9.1`）。
COPY buildSrc/ /tmp/cnb-warmup/buildSrc/
COPY scripts/cnb/warmup-project.sh /opt/cnb/warmup-project.sh
# 注意：RUN 里的续行不能夹注释 —— 行尾 `\` 会把注释行当成命令的一部分传给下一行，
# 曾因此报 `sed: can't read /build.gradle.kts`。注解一律写在这里。
#
# 预热失败必须看得见，但**不能只打 warning 就放行**。早期版本就是
# 「warning + 退出码归零」，把判据全留给运行期；代价是留下一个带残缺缓存的镜像，
# 被 docker:cache 按版本名记住，之后每次流水线都栽在同一个
# `Plugin ... was not found` 上，除了清缓存重建镜像没有别的解法。
#
# 关键点：**联网预热成功证明不了缓存可用** —— 它可以现场冲网把缺的补齐，
# 退出码 0 只说明那一刻网络是通的。所以在联网预热之后，立刻在同一份用户目录上
# 再跑一次「只看缓存」的复核（--offline + -PcnbCacheOnlyCheck，与运行期
# scripts/cnb/setup-build-env.sh 用的是同一个判据）：只查 GRADLE_USER_HOME 里
# 有什么，能过才 `cp -a` 进 /opt/gradle-user-home。两种失败都打网络层证据 +
# 日志尾部，并让镜像构建失败。
#
# 成本只是一个 RUN 层的重建（预热层，几十秒到几分钟），JDK / Gradle / SDK/NDK
# 那几层照旧命中缓存 —— 不是「整个镜像重来」，所以这里判死是划算的。
#
# 预热必须替运行期把东西下全：两个 init script 都显式传（gradle-init.gradle
# 追加 Maven 镜像，gradle-proxy.init.gradle.kts 桥接代理），CNB_BUILD_ID 走
# 同一条分支。预热工程由 scripts/cnb/warmup-project.sh 改写：`plugins {}` +
# `pluginManagement` 保留，**并补上 dependencyResolutionManagement** —— 插件
# buildscript classpath 的解析用的是后者，缺了它只剩隐式的 MavenRepo
# （repo.maven.apache.org），冷启动几十个 POM 必吃 429，预热整段失败。
# 预热与运行期唯一允许的差异是「不给 --offline」（预热的整件工作
# 就是联网）与「用 /opt 下的副本而不是 $GRADLE_USER_HOME/init.d 里的那份」，
# 后者是为了不让 init.d 里那份被重复应用 —— 内容取自同一个文件。
#   * GRADLE_USER_HOME 必须显式给：镜像 ENV 里是 /root/.gradle，而下面 `cp -a`
#     的目标就是它，不给的话 `gradle help` 与 `cp -a` 会指向同一个目录，
#     预热下的依赖会被后面的 `rm -rf /root/.gradle` 一起删掉，等于白预热。
#   * 超时兜底：CI 的代理变量在无网时会变成黑洞（连上去就不说话），Gradle 的
#     仓库超时是「无限」，一次挂起就能把镜像构建卡到被平台杀。联网预热给 15 分钟、
#     只看缓存的复核给 5 分钟上限，kill 之后落到 ERROR 分支 —— 预热不完整就不出镜像。
#     （联网那次比复核重：除了 `help` 还要解析 :app 的整张运行时依赖图。）
#   * 预热失败时除日志尾巴外，先把「网络层证据」单独捞出来（Could not GET/HEAD、
#     429、proxy、Connection、timed out）—— 默认日志只有一句 `BUILD FAILED`，
#     够不到「哪个仓库、什么状态码」，而这一层是整轮里最贵的一次构建。
#   * warmup 走 --info：仓库命中/落空、redirect、重试只在这一档。前几轮排查里
#     「Searched in 有 Google 却报 not found」正是靠这一档才看清是谁返回的 200。
#   * warmup-project.sh 必须用 bash 跑，不能 `sh -x`：Docker 的默认 shell 是
#     dash，而脚本第 21 行是 `set -euo pipefail`，dash 不认 pipefail，直接
#     报 `set: Illegal option -o pipefail` 以退出码 2 结束整层构建 —— 这一步
#     在 if 之外，会让整层直接以退出码 2 结束。脚本自己的 shebang 是 bash，
#     按 shebang 执行即可（镜像基于 ubuntu，bash 恒在）。
#   * **buildSrc 必须被预热，且预热的形状要与运行期一致**。Gradle 只要在
#     settings 所在目录看到 buildSrc/，就会在配置任何工程之前先把它当 included
#     build 编译一遍；而它不继承 settings 的 pluginManagement，`--init-script`
#     传的仓库对它也不生效，插件只能靠自己脚本里那几行去拿。
#
#     于是预热工程的两遍各管一头：
#       - 第一遍按仓库原样跑，真实 buildSrc 连插件 marker 与传递依赖一起进缓存；
#       - 第二遍换成**占位**（scripts/cnb/warmup-project.sh 的
#         stage_buildsrc_placeholder），插件 id 从仓库那份读，只解析、不产出。
#     注意「换成占位」不等于「删掉」：早先第二遍是 `rm -rf buildSrc`，于是预热
#     的工程形状与运行期不同，运行期那份 buildSrc 的插件解析没人替它预热，
#     「校验代码准备」的 `--offline` 复核连续几轮都倒在
#       * Where: Build file '/workspace/buildSrc/build.gradle.kts' line: 23
#       Plugin [id: 'org.gradle.kotlin.kotlin-dsl', version: '6.6.4'] was not found
#     只删 /tmp/cnb-warmup 里的副本，仓库自己的 buildSrc/ 一个字节不碰。
#
#     另一头是 app 脚本里那行 `id("somcp.patched-local-jars")`：**第一遍照常
#     apply**（patched jar 的 `x.y.z.1` 就是它换出来的，预热必须下那套坐标，本地
#     仓库由 warmup-project.sh 的 publish_patched_local_repo 提前铺好）；第二遍的
#     :app 已被换成没有 dependencies {} 的最小脚本，插件自然用不上。
#
#     buildSrc 用 Gradle 自带的 `groovy-gradle-plugin` 而不用 `kotlin-dsl`：
#     后者的 marker 要先从 Portal 下来，而占位里写的正是仓库那份的插件 id ——
#     两边必须是同一个插件，预热下的那套才正好是运行期要的那套。
#   * **预热命令关掉 configuration-cache**：运行期的 gradle.properties 开着它，
#     预热工程每次只有一次执行机会，存下来的配置缓存毫无收益，却在
#     「读:app 的依赖图」这类一次性工程上多一个可能失败的点。
#   * 联网预热用的 GRADLE_USER_HOME 是 /tmp/cnb-warmup-home，而「只看缓存」的
#     复核脚本不在那儿 —— 别再加一步往那个目录里 cp：脚本本体只放 /opt/cnb，
#     两次调用都用 -Dcnb.cacheOnlyScript 显式指过去。早先的做法是
#     `cp /opt/cnb/gradle-cache-only.gradle /tmp/cnb-warmup-home/cnb-cache-only.gradle`，
#     但镜像里那条 COPY 已经改成落 /opt/cnb，这行就变成「从不存在的位置拷」，
#     整层直接以 1 退出（报的还是 no such file），而真正的判据是「缓存全不全」。
#     查找顺序由 gradle-proxy.init.gradle.kts 负责，路径只在这一处出现。
RUN set -eu; \
    cp -a /opt/gradle-user-home /root/.gradle; \
    cd /tmp/cnb-warmup; \
    mkdir -p release; \
    printf 'storeFile=%s\nstorePassword=%s\nkeyAlias=%s\nkeyPassword=%s\n' \
        /tmp/cnb-warmup-signing.jks warmup-only warmup-only warmup-only > release/keystore.properties; \
    keytool -genkeypair -noprompt -storetype JKS \
        -keystore /tmp/cnb-warmup-signing.jks -alias warmup-only \
        -keyalg RSA -keysize 2048 -validity 1 \
        -storepass warmup-only -keypass warmup-only -dname 'CN=warmup' > /dev/null 2>&1; \
    printenv | grep -i '_proxy=' || echo "[warmup] no *_proxy in environment"; \
    bash -x /opt/cnb/warmup-project.sh; \
    if CNB_BUILD_ID=warmup GRADLE_USER_HOME=/tmp/cnb-warmup-home timeout 300 \
         /opt/gradle/bin/gradle --offline --no-daemon --console=plain --info \
         --no-configuration-cache \
         -PcnbCacheOnlyCheck \
         --init-script /opt/cnb/gradle-init.gradle \
         --init-script /opt/cnb/gradle-proxy.init.gradle.kts \
         -Dcnb.cacheOnlyScript=/opt/cnb/gradle-cache-only.gradle \
         help :app:dependencies --configuration releaseRuntimeClasspath \
         > /tmp/cnb-warmup-offline.log 2>&1; then \
      echo "[warmup] cache-only recheck OK: the cache is self-sufficient"; \
      cp -a /tmp/cnb-warmup-home/. /opt/gradle-user-home/; \
    else \
      echo "[warmup] ERROR: cache-only recheck failed. The online warmup only looked" >&2; \
      echo "[warmup] ERROR: successful because the network was reachable; the cache is" >&2; \
      echo "[warmup] ERROR: NOT self-sufficient, and later stages resolve offline." >&2; \
      grep -E "Could not (GET|HEAD|resolve)|rate limit|429|proxy|Connection|timed out|Searched in the following locations" /tmp/cnb-warmup-offline.log | tail -n 40 >&2 || true; \
      tail -n 80 /tmp/cnb-warmup-offline.log >&2 || true; \
      if grep -qE "cnb-(plugin-)?(central-)?mirror-" /tmp/cnb-warmup-offline.log; then \
        echo "[warmup] HINT: a cnb-mirror-* repository is in the rejection list. Load-bearing" >&2; \
        echo "[warmup] HINT: downloads during the ONLINE warmup can go through the Maven Central" >&2; \
        echo "[warmup] HINT: mirror (maven.aliyun.com) while no jitpack/studio mirror serves that" >&2; \
        echo "[warmup] HINT: coordinate; those land in the cache under the mirror's index, so the" >&2; \
        echo "[warmup] HINT: cache-only recheck (empty local repos, ordered like the mirror list)" >&2; \
        echo "[warmup] HINT: rejects them. Add a google mirror far enough down the list, or stop" >&2; \
        echo "[warmup] HINT: warming up with the network reachable (see gradle-init.gradle)." >&2; \
      fi; \
      exit 1; \
    fi; \
    rm -f /tmp/cnb-warmup.log /tmp/cnb-warmup-2.log /tmp/cnb-warmup-offline.log; \
    cd /; rm -rf /tmp/cnb-warmup /tmp/cnb-warmup-home /tmp/cnb-warmup-signing.jks /root/.gradle; \
    du -sh /opt/gradle-user-home

WORKDIR /workspace
