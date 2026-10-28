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
# 「只看缓存」复核脚本：运行期 setup-build-env.sh 传 -PcnbCacheOnlyCheck 时由
# gradle-proxy.init.gradle.kts 从 $GRADLE_USER_HOME 里 apply 它（见该文件注释）。
COPY scripts/cnb/gradle-cache-only.gradle /opt/gradle-user-home/cnb-cache-only.gradle
COPY scripts/cnb/gradle-init.gradle /opt/cnb/gradle-init.gradle

# 预热用的最小工程：插件版本与仓库声明都从仓库自己的构建脚本里读，不另抄一份
# （settings 里手写 google() / mavenCentral() 就等于绕开 settings.gradle.kts，
# 仓库换了源预热也不会跟着换）。
# build.gradle.kts / settings.gradle.kts / gradle.properties 由 .cnb.yml 的
# docker:cache.by 带进构建上下文（docker:cache 只复制 Dockerfile 与 by 声明的
# 文件），因此这三个文件必须显式 COPY 进来 —— 光在 `by` 里声明不会让它们
# 自动出现在镜像里。COPY 的源是上下文根、按仓库相对路径写，不能带 `../`。
#
# 改写的判据（下面那条 RUN 逐条对应）：
#   * build.gradle.kts 只留 `plugins {}` —— 原文件的其余内容（仓库声明、
#     allprojects 等）在只有插件块的最小工程里求值会失败；
#   * settings.gradle.kts 去掉 `rootProject.name` / `include`，只留
#     `pluginManagement { repositories { ... } }` —— **仓库声明必须保留**：
#     早先的做法是把 settings 清空成一行 rootProject.name，Gradle 于是只剩
#     缺省的 gradlePluginPortal，而 AGP 的 marker 在 Google，预热解析
#     `com.android.application:9.2.1` 永远拿不到（镜像层只留 warning，
#     运行期的「只看缓存」复核随后报「warmup cache is incomplete」）；
#   * gradle.properties 必须一起进预热工程 —— 仓库级重试参数
#     （org.gradle.internal.repository.max.tentatives / initial.backoff）与
#     network.retries 都从这份属性文件读，而冷启动最吃重试的正是预热这一次解析；
#     少设一次就是「预热下的东西运行期用不上」，白跑。
COPY build.gradle.kts settings.gradle.kts gradle.properties /tmp/cnb-warmup/
COPY scripts/cnb/warmup-project.sh /opt/cnb/warmup-project.sh
# 注意：RUN 里的续行不能夹注释 —— 行尾 `\` 会把注释行当成命令的一部分传给下一行，
# 曾因此报 `sed: can't read /build.gradle.kts`。注解一律写在这里。
#
# 预热失败必须看得见，但不能让镜像作废：镜像里除了这份缓存还有 JDK / Gradle /
# SDK/NDK（光 sdkmanager 就 3 分钟），为了一次网络抖动重建整个镜像不划算。
# 所以 —— 失败时把日志尾部打到 stderr（Gradle 从 stdout 走，不打出来就只剩一行
# "BUILD FAILED"），然后退出码归零；运行期由 scripts/cnb/setup-build-env.sh
# 以「只看缓存」的方式（--offline + -PcnbCacheOnlyCheck）复核预热结果，缓存不完整
# 就在 stage 里明确失败并指向这里。
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
#     仓库超时是「无限」，一次挂起就能把镜像构建卡到被平台杀。给 10 分钟上限，
#     kill 之后落到下面的 warning 分支，工具链照常产出。
#   * 预热失败时除日志尾巴外，先把「网络层证据」单独捞出来（Could not GET/HEAD、
#     429、proxy、Connection、timed out）—— 默认日志只有一句 `BUILD FAILED`，
#     够不到「哪个仓库、什么状态码」，而这一层是整轮里最贵的一次构建。
#   * warmup 走 --info：仓库命中/落空、redirect、重试只在这一档。前几轮排查里
#     「Searched in 有 Google 却报 not found」正是靠这一档才看清是谁返回的 200。
#   * warmup-project.sh 必须用 bash 跑，不能 `sh -x`：Docker 的默认 shell 是
#     dash，而脚本第 21 行是 `set -euo pipefail`，dash 不认 pipefail，直接
#     报 `set: Illegal option -o pipefail` 以退出码 2 结束整层构建 —— 这一步
#     在 if 之外，所以「预热失败只告警」的兜底根本没机会生效。脚本自己的
#     shebang 是 bash，按 shebang 执行即可（镜像基于 ubuntu，bash 恒在）。
RUN set -eu; \
    cp -a /opt/gradle-user-home /root/.gradle; \
    cd /tmp/cnb-warmup; \
    bash -x /opt/cnb/warmup-project.sh; \
    printenv | grep -i '_proxy=' || echo "[warmup] no *_proxy in environment"; \
    if CNB_BUILD_ID=warmup GRADLE_USER_HOME=/tmp/cnb-warmup-home timeout 600 \
         /opt/gradle/bin/gradle --no-daemon --console=plain --info \
         --init-script /opt/cnb/gradle-init.gradle \
         --init-script /opt/cnb/gradle-proxy.init.gradle.kts \
         help > /tmp/cnb-warmup.log 2>&1; then \
      echo "[warmup] gradle help OK"; \
      cp -a /tmp/cnb-warmup-home/. /opt/gradle-user-home/; \
    else \
      echo "[warmup] WARNING: gradle help failed, image keeps the toolchain but the" >&2; \
      echo "[warmup] WARNING: dependency cache is incomplete; see tail below." >&2; \
      grep -E "Could not (GET|HEAD|resolve)|rate limit|429|proxy|Connection|timed out" /tmp/cnb-warmup.log | tail -n 40 >&2 || true; \
      tail -n 60 /tmp/cnb-warmup.log >&2 || true; \
    fi; \
    rm -f /tmp/cnb-warmup.log; \
    cd /; rm -rf /tmp/cnb-warmup /tmp/cnb-warmup-home /root/.gradle; \
    du -sh /opt/gradle-user-home

WORKDIR /workspace
