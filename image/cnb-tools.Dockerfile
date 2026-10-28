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
      python3 python3-pip python3-venv \
      meson ninja-build cmake gcc g++ pkg-config make patch \
      autoconf automake libtool libarchive-tools openssh-client \
 && rm -rf /var/lib/apt/lists/*

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
# 运行期 /root/.gradle 是 data 卷，首次挂载为空，由 scripts/cnb/setup-build-env.sh
# 从 /opt/gradle-user-home 搬进去；镜像层保留原件，卷随流水线销毁。
COPY scripts/cnb/gradle-init.gradle /opt/gradle-user-home/init.d/cnb-init.gradle

# 预热用的最小工程：插件版本与仓库声明都从仓库自己的构建脚本里读，不另抄一份。
RUN set -eu; \
    cp -a /opt/gradle-user-home /root/.gradle; \
    mkdir -p /tmp/cnb-warmup; \
    cd /tmp/cnb-warmup; \
    sed -n '/^plugins {/,/^}/p' /workspace/build.gradle.kts > build.gradle.kts; \
    sed -n '/^pluginManagement {/,/^}/p' /workspace/settings.gradle.kts > settings.gradle.kts; \
    printf 'rootProject.name = "cnb-warmup"\n' >> settings.gradle.kts; \
    grep -q 'org.jetbrains.kotlin.android' build.gradle.kts; \
    gradle --no-daemon --console=plain help; \
    cd /; rm -rf /tmp/cnb-warmup /root/.gradle/daemon /root/.gradle/.tmp; \
    rm -rf /root/.gradle; \
    du -sh /opt/gradle-user-home

WORKDIR /workspace
