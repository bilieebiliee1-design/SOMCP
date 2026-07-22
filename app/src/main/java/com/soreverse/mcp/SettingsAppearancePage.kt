package com.soreverse.mcp

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.unit.dp

@Composable
internal fun SettingsAppearancePage(
    t: UiText,
    language: String,
    onLanguage: (String) -> Unit,
    themeMode: String,
    onTheme: (String) -> Unit,
    accentColor: String,
    onAccent: (String) -> Unit,
    pureBlackDark: Boolean,
    onPureBlack: (Boolean) -> Unit,
    uiDensity: String,
    onDensity: (String) -> Unit,
    cornerStyle: String,
    onCorner: (String) -> Unit,
    motionMode: String,
    onMotion: (String) -> Unit,
    showAdvancedHome: Boolean,
    onShowAdvancedHome: (Boolean) -> Unit,
    highContrast: Boolean,
    onHighContrast: (Boolean) -> Unit,
    textScale: String,
    onTextScale: (String) -> Unit,
    predictiveBack: Boolean,
    onPredictiveBack: (Boolean) -> Unit,
) {
    PageScroll {
        SurfacePanel {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp), horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth()) {
                Text(if (t.zh) "实时预览" else "Live preview", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Box(
                    Modifier
                        .size(64.dp)
                        .clip(CircleShape)
                        .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.16f))
                        .border(BorderStroke(2.dp, MaterialTheme.colorScheme.primary.copy(alpha = 0.35f)), CircleShape),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(Icons.Default.PlayArrow, null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(28.dp))
                }
                Text(if (t.zh) "强调色会立刻影响按钮与选中态" else "Accent updates buttons and selection immediately", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                PrimaryActionButton(if (t.zh) "示例主按钮" else "Sample primary", onClick = {}, modifier = Modifier.fillMaxWidth())
            }
        }
        GlassGroup(title = t.language) {
            ChipRow(listOf("system" to if (t.zh) "跟随系统" else "System", "zh" to "中文", "en" to "English"), language, onLanguage)
        }
        GlassGroup(title = t.theme) {
            ChipRow(listOf("system" to if (t.zh) "跟随系统" else "System", "light" to if (t.zh) "浅色" else "Light", "dark" to if (t.zh) "深色" else "Dark"), themeMode, onTheme)
        }
        GlassGroup(title = if (t.zh) "强调色" else "Accent") {
            ChipRow(
                listOf(
                    "blue" to if (t.zh) "蓝" else "Blue",
                    "teal" to if (t.zh) "青" else "Teal",
                    "indigo" to if (t.zh) "靛" else "Indigo",
                    "purple" to if (t.zh) "紫" else "Purple",
                    "green" to if (t.zh) "绿" else "Green",
                    "orange" to if (t.zh) "橙" else "Orange",
                    "red" to if (t.zh) "红" else "Red",
                    "mono" to if (t.zh) "灰" else "Mono",
                ),
                accentColor,
                onAccent,
            )
        }
        GlassGroup(title = if (t.zh) "布局密度" else "Density") {
            ChipRow(
                listOf(
                    "compact" to if (t.zh) "紧凑" else "Compact",
                    "comfortable" to if (t.zh) "舒适" else "Comfortable",
                    "spacious" to if (t.zh) "宽松" else "Spacious",
                ),
                uiDensity,
                onDensity,
            )
        }
        GlassGroup(title = if (t.zh) "圆角" else "Corners") {
            ChipRow(
                listOf(
                    "small" to if (t.zh) "小" else "Small",
                    "medium" to if (t.zh) "中" else "Medium",
                    "large" to if (t.zh) "大" else "Large",
                    "xlarge" to if (t.zh) "特大" else "XL",
                ),
                cornerStyle,
                onCorner,
            )
        }
        GlassGroup(title = if (t.zh) "字号" else "Text size") {
            ChipRow(
                listOf(
                    "normal" to if (t.zh) "标准" else "Normal",
                    "large" to if (t.zh) "大" else "Large",
                    "xlarge" to if (t.zh) "特大" else "XL",
                ),
                textScale,
                onTextScale,
            )
        }
        GlassGroup(title = if (t.zh) "动效" else "Motion") {
            ChipRow(
                listOf(
                    "system" to if (t.zh) "跟随系统" else "System",
                    "full" to if (t.zh) "标准" else "Full",
                    "reduced" to if (t.zh) "减弱" else "Reduced",
                ),
                motionMode,
                onMotion,
            )
        }
        GlassGroup {
            ToggleRow(if (t.zh) "纯黑深色背景" else "Pure black dark mode", pureBlackDark, onPureBlack)
            GroupDivider()
            ToggleRow(if (t.zh) "高对比" else "High contrast", highContrast, onHighContrast)
            GroupDivider()
            ToggleRow(t.predictiveBack, predictiveBack, onPredictiveBack)
        }
    }
}
