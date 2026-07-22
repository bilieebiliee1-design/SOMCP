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
        GlassGroup(footer = if (t.zh) "排名不分先后。点击条目可打开项目主页。" else "Listed in no particular order. Tap an item to open its homepage.") {
            Text(
                if (t.zh) "以下项目和工具提供了直接依赖、运行基础、工程参考或工作流参考。" else "These projects provide dependencies, runtime foundations, or workflow references.",
                modifier = Modifier.padding(14.dp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        CreditGroup(if (t.zh) "核心逆向与原生能力" else "Reverse-engineering core", listOf(
            CreditProject("Rizin", if (t.zh) "反汇编、汇编、分析与搜索核心" else "Disasm / asm / analysis / search core", "https://github.com/rizinorg/rizin"),
            CreditProject("LIEF", if (t.zh) "ELF 解析、修复与重写基础" else "ELF parsing / repair / rewriting", "https://github.com/lief-project/LIEF"),
            CreditProject("Unidbg", if (t.zh) "Android SO 级原生模拟执行" else "Android native emulation", "https://github.com/zhkl0228/unidbg"),
            CreditProject("xAnSo", if (t.zh) "SO 节区头重建算法参考" else "Section header reconstruction reference", "https://github.com/HexHacking/xAnSo"),
            CreditProject("Capstone", if (t.zh) "依赖链中使用的反汇编引擎" else "Disassembly engine used by dependencies", "https://github.com/capstone-engine/capstone"),
            CreditProject("Keystone", if (t.zh) "依赖链中使用的汇编引擎" else "Assembly engine used by dependencies", "https://github.com/keystone-engine/keystone"),
            CreditProject("Unicorn", if (t.zh) "依赖链中使用的 CPU 模拟引擎" else "CPU emulation used by dependencies", "https://github.com/unicorn-engine/unicorn"),
        ))
        CreditGroup(if (t.zh) "Android 与界面基础" else "Android and UI foundation", listOf(
            CreditProject("AndroidX", if (t.zh) "Android 应用基础支持库" else "Android support libraries", "https://developer.android.com/jetpack/androidx"),
            CreditProject("Jetpack Compose", if (t.zh) "声明式界面框架" else "Declarative UI toolkit", "https://developer.android.com/jetpack/compose"),
            CreditProject("Material Design 3", if (t.zh) "界面组件与设计规范" else "UI components and design system", "https://m3.material.io/"),
            CreditProject("Kotlin", if (t.zh) "主要开发语言与工具链" else "Language and toolchain", "https://github.com/JetBrains/kotlin"),
            CreditProject("kotlinx.coroutines", if (t.zh) "协程与异步任务运行时" else "Coroutine runtime", "https://github.com/Kotlin/kotlinx.coroutines"),
            CreditProject("kotlinx.serialization", if (t.zh) "序列化能力基础" else "Serialization runtime", "https://github.com/Kotlin/kotlinx.serialization"),
        ))
        CreditGroup(if (t.zh) "网络、服务与构建" else "Networking, server, and build", listOf(
            CreditProject("Ktor", if (t.zh) "内置 MCP HTTP 服务基础" else "Embedded MCP HTTP server", "https://github.com/ktorio/ktor"),
            CreditProject("OkHttp", if (t.zh) "HTTP 客户端与探测请求" else "HTTP client", "https://github.com/square/okhttp"),
            CreditProject("Okio", if (t.zh) "高效 I/O 基础库" else "I/O primitives", "https://github.com/square/okio"),
            CreditProject("SLF4J", if (t.zh) "日志门面与依赖链日志基础" else "Logging facade", "https://github.com/qos-ch/slf4j"),
            CreditProject("Typesafe Config", if (t.zh) "配置解析基础库" else "Configuration library", "https://github.com/lightbend/config"),
            CreditProject("cloudflared", if (t.zh) "Cloudflare Tunnel 公网隧道能力" else "Cloudflare Tunnel", "https://github.com/cloudflare/cloudflared"),
            CreditProject("Gradle", if (t.zh) "项目构建系统" else "Build system", "https://github.com/gradle/gradle"),
            CreditProject("Android Gradle Plugin", if (t.zh) "Android 构建与打包集成" else "Android build integration", "https://developer.android.com/build"),
            CreditProject("Android NDK", if (t.zh) "原生库交叉编译工具链" else "Native build toolchain", "https://developer.android.com/ndk"),
        ))
        CreditGroup(if (t.zh) "依赖与参考工具" else "Dependencies and reference tools", listOf(
            CreditProject("JNA", if (t.zh) "依赖链中的原生访问能力" else "Native access used by dependencies", "https://github.com/java-native-access/jna"),
            CreditProject("apk-parser", if (t.zh) "依赖链中的 APK 解析能力" else "APK parsing used by dependencies", "https://github.com/hsiafan/apk-parser"),
            CreditProject("Apache Commons Codec", if (t.zh) "编解码工具基础库" else "Codec utilities", "https://commons.apache.org/proper/commons-codec/"),
            CreditProject("Apache Commons IO", if (t.zh) "I/O 工具基础库" else "I/O utilities", "https://commons.apache.org/proper/commons-io/"),
            CreditProject("Apache Commons Collections", if (t.zh) "集合工具基础库" else "Collection utilities", "https://commons.apache.org/proper/commons-collections/"),
            CreditProject("fastjson", if (t.zh) "依赖链中的 JSON 工具" else "JSON utilities used by dependencies", "https://github.com/alibaba/fastjson"),
            CreditProject("native-lib-loader", if (t.zh) "依赖链中的原生库加载工具" else "Native library loading", "https://github.com/scijava/native-lib-loader"),
            CreditProject("MT 管理器 / MT Manager", if (t.zh) "APK 工作流参考与 APK MCP 能力来源" else "APK workflow reference and APK MCP provider", "https://mt2.cn/"),
        ))
    }
}

private data class CreditProject(val name: String, val role: String, val url: String)

@Composable
private fun CreditGroup(title: String, projects: List<CreditProject>) {
    val context = LocalContext.current
    GlassGroup(title = title) {
        projects.forEachIndexed { idx, project ->
            if (idx > 0) GroupDivider()
            NavRow(project.name, project.role, Icons.Default.Link, onClick = { openUrl(context, project.url) })
        }
    }
}

private fun openUrl(context: Context, url: String) {
    val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    runCatching { context.startActivity(intent) }
        .onFailure { Toast.makeText(context, url, Toast.LENGTH_SHORT).show() }
}
