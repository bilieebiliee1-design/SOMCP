package com.soreverse.mcp

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

@Composable
internal fun SettingsBlutterPage(t: UiText) {
    PageScroll {
        GlassGroup {
            Column(Modifier.padding(14.dp)) {
                Text(if (t.zh) "内置版本" else "Embedded version", fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.titleMedium)
                Text("Flutter 3.44.x · Dart 3.12.2 · arm64-v8a", color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.bodyMedium)
                Text(
                    if (t.zh) "当前发行版只打包这一套完整分析 Runner，以控制安装包体积。分析完全在手机本地完成，不需要 Python、网络、ADB 或远端服务。" else "This release embeds one full analysis runner to control package size. Analysis runs locally without Python, network, ADB, or remote services.",
                    modifier = Modifier.padding(top = 10.dp),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            GroupDivider()
            Column(Modifier.padding(14.dp)) {
                Text(if (t.zh) "兼容性规则" else "Compatibility", fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.titleSmall)
                Text(
                    if (t.zh) "仅当目标 APK 的 snapshot hash、ABI 和压缩指针模式与内置 Runner 精确匹配时才会启动分析。其他 Flutter/Dart 版本会明确返回不支持，不会尝试错误解析。" else "Analysis starts only when snapshot hash, ABI, and compressed-pointer mode exactly match the embedded runner. Other Flutter/Dart versions return an explicit unsupported-version error.",
                    modifier = Modifier.padding(top = 8.dp),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}
