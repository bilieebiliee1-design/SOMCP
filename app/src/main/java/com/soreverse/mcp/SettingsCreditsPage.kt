// SPDX-License-Identifier: GPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
package com.soreverse.mcp

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Link
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp

@Composable
internal fun SettingsCreditsPage(t: UiText) {
    PageScroll {
        GlassGroup(
            title = "${com.soreverse.mcp.core.Provenance.PROJECT} · ${com.soreverse.mcp.core.Provenance.LICENSE}",
            footer = com.soreverse.mcp.core.Provenance.COPYRIGHT
        ) {
            Text(
                if (t.zh) {
                    "本软件为 GPL-3.0-only 自由软件。再分发（含修改、改名、二次打包版本）必须保留版权与许可声明、继续以 GPL-3.0-only 授权、提供完整对应源代码。上游唯一官方来源："
                } else {
                    "SOMCP is GPL-3.0-only free software. Redistribution must retain notices, remian under GPL-3.0-only, and provide complete corresponding source. Upstream: "
                },
                modifier = Modifier.padding(14.dp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        GlassGroup(
            footer = if (t.zh) "排名不分先后。点击条目可打开项目主页。" else "Listed in no particular order. Tap an item to open its homepage."
        ) {
            Text(
                if (t.zh) "以下项目和工具提供了直接依赖、运行基础、工程参考或工作流参考。" else "These projects provide dependencies, runtime foundations, or workflow references.",
                modifier = Modifier.padding(14.dp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        CreditGroup(
            if (t.zh) "核心逆向与原生能力" else "Reverse-engineering core",
            listOf(
                CreditProject(
                    "Rizin",
                    if (t.zh) "反汇编、汇编、分析与搜索核心" else "Disasm / asm / analysis / search core",
                    "https://github.com/rizinorg/rizin"
                ),
                CreditProject(
                    "LIEF",
                    if (t.zh) "ELF 解析、修复与重写基础" else "ELF parsing / repair / rewriting",
                    "https://github.com/lief-project/LIEF"
                ),
                CreditProject(
                    "Unidbg",
                    if (t.zh) "Android SO 级原生模拟执行" else "Android native emulation",
                    "https://github.com/zhkl0228/unidbg"
                ),
                CreditProject(
                    "xAnSo",
                    if (t.zh) "SO 节区头重建算法参考" else "Section header reconstruction reference",
                    "https://github.com/HexHacking/xAnSo"
                ),
                CreditProject(
                    "Capstone",
                    if (t.zh) "依赖链中使用的反汇编引擎" else "Disassembly engine used by dependencies",
                    "https://github.com/capstone-engine/capstone"
                ),
                CreditProject(
                    "Keystone",
                    if (t.zh) "依赖链中使用的汇编引擎" else "Assembly engine used by dependencies",
                    "https://github.com/keystone-engine/keystone"
                ),
                CreditProject(
                    "Unicorn",
                    if (t.zh) "依赖链中使用的 CPU 模拟引擎" else "CPU emulation used by dependencies",
                    "https://github.com/unicorn-engine/unicorn"
                ),
                CreditProject(
                    "Blutter",
                    if (t.zh) "离线 Flutter Android AOT 分析引擎（内嵌 Runner）" else "Embedded offline Flutter Android AOT analysis engine",
                    "https://github.com/worawit/blutter"
                )
            )
        )
        CreditGroup(
            if (t.zh) "Android 与界面基础" else "Android and UI foundation",
            listOf(
                CreditProject(
                    "AndroidX",
                    if (t.zh) "Android 应用基础支持库" else "Android support libraries",
                    "https://developer.android.com/jetpack/androidx"
                ),
                CreditProject(
                    "Jetpack Compose",
                    if (t.zh) "声明式界面框架" else "Declarative UI toolkit",
                    "https://developer.android.com/jetpack/compose"
                ),
                CreditProject(
                    "Material Design 3",
                    if (t.zh) "界面组件与设计规范" else "UI components and design system",
                    "https://m3.material.io/"
                ),
                CreditProject(
                    "Kotlin",
                    if (t.zh) "主要开发语言与工具链" else "Language and toolchain",
                    "https://github.com/JetBrains/kotlin"
                ),
                CreditProject(
                    "kotlinx.coroutines",
                    if (t.zh) "协程与异步任务运行时" else "Coroutine runtime",
                    "https://github.com/Kotlin/kotlinx.coroutines"
                ),
                CreditProject(
                    "kotlinx.serialization",
                    if (t.zh) "序列化能力基础" else "Serialization runtime",
                    "https://github.com/Kotlin/kotlinx.serialization"
                )
            )
        )
        CreditGroup(
            if (t.zh) "网络、服务与构建" else "Networking, server, and build",
            listOf(
                CreditProject(
                    "Ktor",
                    if (t.zh) "内置 MCP HTTP 服务基础" else "Embedded MCP HTTP server",
                    "https://github.com/ktorio/ktor"
                ),
                CreditProject(
                    "OkHttp",
                    if (t.zh) "HTTP 客户端与探测请求" else "HTTP client",
                    "https://github.com/square/okhttp"
                ),
                CreditProject(
                    "Okio",
                    if (t.zh) "高效 I/O 基础库" else "I/O primitives",
                    "https://github.com/square/okio"
                ),
                CreditProject(
                    "SLF4J",
                    if (t.zh) "日志门面与依赖链日志基础" else "Logging facade",
                    "https://github.com/qos-ch/slf4j"
                ),
                CreditProject(
                    "Typesafe Config",
                    if (t.zh) "配置解析基础库" else "Configuration library",
                    "https://github.com/lightbend/config"
                ),
                CreditProject(
                    "cloudflared",
                    if (t.zh) "Cloudflare Tunnel 公网隧道能力" else "Cloudflare Tunnel",
                    "https://github.com/cloudflare/cloudflared"
                ),
                CreditProject(
                    "Gradle",
                    if (t.zh) "项目构建系统" else "Build system",
                    "https://github.com/gradle/gradle"
                ),
                CreditProject(
                    "Android Gradle Plugin",
                    if (t.zh) "Android 构建与打包集成" else "Android build integration",
                    "https://developer.android.com/build"
                ),
                CreditProject(
                    "Android NDK",
                    if (t.zh) "原生库交叉编译工具链" else "Native build toolchain",
                    "https://developer.android.com/ndk"
                )
            )
        )
        CreditGroup(
            if (t.zh) "依赖与参考工具" else "Dependencies and reference tools",
            listOf(
                CreditProject(
                    "JNA",
                    if (t.zh) "依赖链中的原生访问能力" else "Native access used by dependencies",
                    "https://github.com/java-native-access/jna"
                ),
                CreditProject(
                    "apk-parser",
                    if (t.zh) "依赖链中的 APK 解析能力" else "APK parsing used by dependencies",
                    "https://github.com/hsiafan/apk-parser"
                ),
                CreditProject(
                    "Apache Commons Codec",
                    if (t.zh) "编解码工具基础库" else "Codec utilities",
                    "https://commons.apache.org/proper/commons-codec/"
                ),
                CreditProject(
                    "Apache Commons IO",
                    if (t.zh) "I/O 工具基础库" else "I/O utilities",
                    "https://commons.apache.org/proper/commons-io/"
                ),
                CreditProject(
                    "Apache Commons Collections",
                    if (t.zh) "集合工具基础库" else "Collection utilities",
                    "https://commons.apache.org/proper/commons-collections/"
                ),
                CreditProject(
                    "fastjson",
                    if (t.zh) "依赖链中的 JSON 工具" else "JSON utilities used by dependencies",
                    "https://github.com/alibaba/fastjson"
                ),
                CreditProject(
                    "native-lib-loader",
                    if (t.zh) "依赖链中的原生库加载工具" else "Native library loading",
                    "https://github.com/scijava/native-lib-loader"
                ),
                CreditProject(
                    "MT 管理器 / MT Manager",
                    if (t.zh) "APK 工作流参考与 APK MCP 能力来源" else "APK workflow reference and APK MCP provider",
                    "https://mt2.cn/"
                ),
                CreditProject(
                    "argon2kt",
                    if (t.zh) "备份加密的 Argon2 密钥派生库" else "Argon2 key derivation for encrypted backup",
                    "https://github.com/lambdapioneer/argon2kt"
                ),
                CreditProject(
                    "jsoup",
                    if (t.zh) "HTML 解析与清理" else "HTML parsing and sanitization",
                    "https://github.com/jhy/jsoup"
                ),
                CreditProject(
                    "Markdown (rikkahub)",
                    if (t.zh) "Markdown 渲染基础库" else "Markdown rendering library",
                    "https://github.com/rikkahub/Markdown"
                ),
                CreditProject(
                    "demumble",
                    if (t.zh) "依赖链中的符号反混淆" else "Demangling used by dependencies",
                    "https://github.com/zhkl0228/demumble"
                ),
                CreditProject(
                    "ApkSignatureKillerEx",
                    if (t.zh) "APK 签名校验绕过与重打包参考工具" else "APK signature-bypass and repack reference tool",
                    "https://github.com/L-JINBIN/ApkSignatureKillerEx"
                ),
                CreditProject(
                    "ApkSignatureKiller",
                    if (t.zh) "APK 签名校验绕过参考工具" else "APK signature-bypass reference tool",
                    "https://github.com/L-JINBIN/ApkSignatureKiller"
                ),
                CreditProject(
                    "kstools",
                    if (t.zh) "工程与逆向参考工具集" else "Reverse-engineering reference toolkit",
                    "https://github.com/fourbrother/kstools"
                ),
                CreditProject(
                    "TweakMe",
                    if (t.zh) "APK 修改与返调试参考工具" else "APK patching reference tool",
                    "https://github.com/liaoguobao/TweakMe"
                ),
                CreditProject(
                    "SignatureKiller",
                    if (t.zh) "APK 签名校验绕过参考工具" else "APK signature-bypass reference tool",
                    "https://github.com/Familyye/SignatureKiller"
                ),
                CreditProject(
                    "SigKill",
                    if (t.zh) "APK 签名校验绕过相关参考工具" else "APK signature-bypass related reference tool",
                    "https://github.com/xxxyanchenxxx/SigKill"
                )
            )
        )
    }
}

@Composable
internal fun SettingsDevelopmentCreditsPage(t: UiText) {
    PageScroll {
        GlassGroup(
            footer = if (t.zh) "排名不分先后。点击条目可打开个人主页。" else "Listed in no particular order. Tap an item to open a profile."
        ) {
            Text(
                if (t.zh) "感谢以下开发者与维护者对 SOMCP 的代码、测试与维护做出的贡献。" else "Thanks to the following developers and maintainers for their contributions to SOMCP.",
                modifier = Modifier.padding(14.dp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        CreditGroup(
            if (t.zh) "开发致谢" else "Development acknowledgements",
            listOf(
                CreditProject(
                    "Hello666cpu",
                    if (t.zh) "核心开发者" else "Core developer",
                    "https://github.com/Hello666cpu"
                ),
                CreditProject(
                    "yallex",
                    if (t.zh) "贡献者" else "Contributor",
                    "https://github.com/yallex"
                ),
                CreditProject(
                    "rhoggs-bot-test-account",
                    if (t.zh) "贡献者" else "Contributor",
                    "https://github.com/rhoggs-bot-test-account"
                ),
                CreditProject(
                    "bilieebiliee1-design",
                    if (t.zh) "项目维护者" else "Maintainer",
                    "https://github.com/bilieebiliee1-design"
                ),
                CreditProject(
                    "superman32432432",
                    if (t.zh) "贡献者" else "Contributor",
                    "https://github.com/superman32432432"
                )
            )
        )
    }
}

private data class CreditProject(val name: String, val role: String, val url: String)

@Composable
private fun CreditGroup(title: String, projects: List<CreditProject>) {
    val context = LocalContext.current
    GlassGroup(title = title) {
        projects.forEachIndexed { idx, project ->
            if (idx > 0) GroupDivider()
            NavRow(project.name, project.role, Icons.Default.Link, onClick = {
                openUrl(context, project.url)
            })
        }
    }
}

private fun openUrl(context: Context, url: String) {
    val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    runCatching { context.startActivity(intent) }
        .onFailure { Toast.makeText(context, url, Toast.LENGTH_SHORT).show() }
}
