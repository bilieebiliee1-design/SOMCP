package com.soreverse.mcp

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.animation.togetherWith
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.json.JSONObject
import java.util.Locale

@OptIn(androidx.compose.foundation.layout.ExperimentalLayoutApi::class)
@Composable
internal fun ElfOverviewPanel(detail: SoDetailUi, zh: Boolean, onCopy: (String) -> Unit) {
    val ov = detail.overview
    val sc = ov.optJSONObject("segmentClass") ?: JSONObject()
    val sp = ov.optJSONObject("segmentPermissions") ?: JSONObject()
    val entropy = ov.optJSONObject("entropy") ?: JSONObject()
    val difficulty = ov.optJSONObject("difficulty") ?: JSONObject()
    val security = ov.optJSONArray("securityFeatures") ?: org.json.JSONArray()
    val needed = ov.optJSONArray("neededLibraries") ?: org.json.JSONArray()
    val factors = difficulty.optJSONArray("factors") ?: org.json.JSONArray()
    val recommend = difficulty.optJSONArray("recommend") ?: org.json.JSONArray()
    val attack = ov.optJSONArray("attackSurface") ?: org.json.JSONArray()
    val buckets = entropy.optJSONArray("buckets") ?: org.json.JSONArray()
    val bucketValues = remember(buckets.toString()) {
        (0 until buckets.length()).map { buckets.optDouble(it, 0.0) }
    }
    val strippedFallback = ov.optBoolean("stripped", detail.stripped)
    val totallyStripped = ov.optBoolean("totallyStripped", false)
    var selectedSecurityId by remember(detail.path) { mutableStateOf<String?>(null) }

    Column(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        if (strippedFallback) {
            OverviewAlert(
                title = if (zh) "检测到符号表严重缺失 (Stripped)" else "Symbol table heavily stripped",
                body = if (zh) {
                    buildString {
                        append("该二进制的内部符号表（.symtab）已被剥离，未导出函数通常不再保留原始名称，静态按名定位会更困难。")
                        if (totallyStripped) append("当前动态符号也非常稀少，可用命名线索更有限。")
                        append("MCP 实际分析不会把函数强制命名为 sub_xxx；有符号时沿用真实符号名，无符号时多通过地址定位（如 fcn.xxxx / so_function:...@0x...），并由反汇编/启发式恢复函数边界。")
                    }
                } else {
                    buildString {
                        append("The internal symbol table (.symtab) appears stripped, so unrecovered functions usually lack original names. ")
                        if (totallyStripped) append("Dynamic symbols are also scarce. ")
                        append("MCP analysis does not force sub_xxx names; it keeps real symbol names when present, otherwise uses address-based locators (fcn.xxxx / so_function:...@0x...) with disassembly heuristics.")
                    }
                },
            )
        }

        OverviewSectionCard(title = if (zh) "📦 文件基础属性" else "📦 File basics") {
            OverviewKv(if (zh) "名称" else "Name", ov.optString("fileName", detail.name))
            OverviewKv(if (zh) "大小" else "Size", formatBytes(ov.optLong("size", 0L)))
            OverviewKv(if (zh) "类型" else "Type", ov.optString("elfType", "—"))
            OverviewKv(if (zh) "架构" else "Arch", ov.optString("architecture", "${detail.architecture}/${detail.bits}"))
            OverviewKv(if (zh) "位数" else "Bits", if (ov.optInt("bits", detail.bits) == 64) "64-bit" else "${ov.optInt("bits", detail.bits)}-bit")
            OverviewKv(if (zh) "字节序" else "Endian", ov.optString("endian", "—"))
            OverviewKv(if (zh) "入口" else "Entry", ov.optString("entryPoint", detail.entryPoint), mono = true)
            OverviewKv(if (zh) "加载基址" else "Base", ov.optString("baseAddr", "0x0"), mono = true)
            OverviewKv("SHA-256", ov.optString("sha256", "—"), mono = true, maxLines = 2, onClick = {
                val hash = ov.optString("sha256")
                if (hash.isNotBlank()) onCopy(hash)
            })
            val buildId = ov.optString("buildId")
            if (buildId.isNotBlank()) OverviewKv("Build ID", buildId, mono = true)
            val soname = ov.optString("soname")
            if (soname.isNotBlank()) OverviewKv("SONAME", soname, mono = true)
        }

        OverviewSectionCard(title = if (zh) "📊 结构与规模" else "📊 Structure & scale") {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OverviewMetric(if (zh) "节区" else "Sections", ov.optInt("sectionCount", detail.sectionCount).toString(), Modifier.weight(1f))
                OverviewMetric(if (zh) "程序段" else "Segments", ov.optInt("segmentCount", 0).toString(), Modifier.weight(1f))
                OverviewMetric(if (zh) "函数" else "Functions", ov.optInt("functionCount", 0).toString(), Modifier.weight(1f))
                OverviewMetric(if (zh) "字符串" else "Strings", ov.optInt("stringCount", detail.stringCount).toString(), Modifier.weight(1f))
            }
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OverviewMetric(if (zh) "代码段" else "Exec", "${sc.optInt("execCount")} · ${formatBytes(sc.optLong("execSize"))}", Modifier.weight(1f), Color(0xFFDC3545))
                OverviewMetric(if (zh) "只读段" else "Read", "${sc.optInt("readCount")} · ${formatBytes(sc.optLong("readSize"))}", Modifier.weight(1f), Color(0xFF28A745))
                OverviewMetric(if (zh) "可写段" else "Write", "${sc.optInt("writeCount")} · ${formatBytes(sc.optLong("writeSize"))}", Modifier.weight(1f), Color(0xFFFFA000))
            }
            OverviewKv(
                if (zh) "加载权限" else "Load permissions",
                "R ${sp.optInt("readable")}  ·  W ${sp.optInt("writable")}  ·  X ${sp.optInt("executable")}  ·  PT_LOAD ${sp.optInt("loadable")}",
                mono = true,
            )
            OverviewKv(if (zh) "导入符号" else "Imports", ov.optInt("importCount", 0).toString(), boldValue = true)
            OverviewKv(if (zh) "导出符号" else "Exports", ov.optInt("exportCount", 0).toString(), boldValue = true)
            OverviewKv(if (zh) "依赖库数" else "Needed libs", ov.optInt("neededCount", 0).toString(), boldValue = true)
            OverviewKv(if (zh) "符号 / 动态符号" else "Sym / Dynsym", "${detail.symbolCount} / ${detail.dynsymCount}")
        }

        OverviewSectionCard(title = if (zh) "🛡️ 逆向与系统级安全特征检测" else "🛡️ Security features") {
            Text(
                if (zh) "点击标签查看说明，再次点击可收起" else "Tap a chip for details; tap again to collapse",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            SecurityFeatureCloud(
                security = security,
                selectedId = selectedSecurityId,
                onSelect = { id -> selectedSecurityId = if (selectedSecurityId == id) null else id },
            )
            AnimatedContent(
                targetState = selectedSecurityId,
                transitionSpec = {
                    (fadeIn(tween(130)) + expandVertically(tween(150), expandFrom = Alignment.Top)) togetherWith
                        (fadeOut(tween(80)) + shrinkVertically(tween(100), shrinkTowards = Alignment.Top))
                },
                label = "security-detail",
            ) { selectedId ->
                (0 until security.length())
                    .mapNotNull { security.optJSONObject(it) }
                    .firstOrNull { it.optString("id") == selectedId }
                    ?.let { item ->
                    SecurityFeatureDetail(
                        label = item.optString("label"),
                        tone = item.optString("tone", "ok"),
                        description = item.optString("description"),
                    )
                }
            }
        }

        ReferenceOverviewCard(title = if (zh) "🎯 逆向可行性分析报告" else "🎯 Reverse feasibility") {
            val diffCls = difficulty.optString("cls", "ok")
            DifficultyHeader(
                score = difficulty.optString("score", "0.0"),
                level = difficulty.optString("level", if (zh) "简单" else "Easy"),
                cls = diffCls,
                zh = zh,
            )
            SectionTitleColored(
                text = if (zh) "🔴 难度加分因素：" else "🔴 Difficulty factors:",
                color = Color(0xFF495566),
            )
            if (factors.length() == 0) {
                Text(
                    if (zh) "未检测到显著加固/混淆特征" else "No major hardening/obfuscation signals",
                    style = MaterialTheme.typography.bodySmall,
                    color = Color(0xFF28A745),
                    fontWeight = FontWeight.SemiBold,
                )
            } else {
                Column {
                    for (i in 0 until factors.length()) {
                        val raw = factors.opt(i)
                        val item = raw as? JSONObject
                        val text = item?.optString("text")?.takeIf(String::isNotBlank)
                            ?: item?.optString("title")?.takeIf(String::isNotBlank)
                            ?: factors.optString(i)
                        ReferenceReportLine("• ${text.removePrefix("• ")}", divider = i < factors.length() - 1)
                    }
                }
            }
            SectionTitleColored(
                text = if (zh) "💡 推荐逆向方法与工具：" else "💡 Recommended methods:",
                color = Color(0xFF495566),
            )
            Column(
                Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(4.dp))
                    .background(Color(0xFFF8FAF9))
                    .border(BorderStroke(1.dp, Color(0xFFE8ECE9)), RoundedCornerShape(4.dp))
                    .padding(horizontal = 12.dp, vertical = 8.dp),
            ) {
                for (i in 0 until recommend.length()) {
                    val raw = recommend.opt(i)
                    val item = raw as? JSONObject
                    val text = item?.optString("text")?.takeIf(String::isNotBlank)
                        ?: item?.optString("detail")?.takeIf(String::isNotBlank)
                        ?: recommend.optString(i)
                    Text(
                        "• ${text.removePrefix("• ").trim()}",
                        fontSize = 12.sp,
                        lineHeight = 22.sp,
                        color = Color(0xFF444444),
                    )
                }
            }
            SectionTitleColored(
                text = if (zh) "📋 攻击面与入口点分析：" else "📋 Attack surface:",
                color = Color(0xFF495566),
            )
            Column {
                for (i in 0 until attack.length()) {
                    val raw = attack.opt(i)
                    val item = raw as? JSONObject
                    val id = item?.optString("id").orEmpty()
                    if (id == "dlopen") continue
                    val text = item?.optString("text")?.takeIf(String::isNotBlank)
                        ?: buildString {
                            append("• ")
                            append(item?.optString("title").orEmpty())
                            item?.optString("value").orEmpty().takeIf(String::isNotBlank)?.let { append("：$it") }
                            item?.optString("detail").orEmpty().takeIf(String::isNotBlank)?.let { append(it) }
                        }.takeIf(String::isNotBlank)
                        ?: attack.optString(i)
                    Text(
                        text,
                        fontSize = 12.sp,
                        lineHeight = 22.sp,
                        color = if (id == "dyn_reg" || id == "init_array" || text.contains("⚠")) Color(0xFFD73A49) else Color(0xFF444444),
                        fontWeight = if (id == "dyn_reg" || id == "init_array" || text.contains("⚠")) FontWeight.Bold else FontWeight.Normal,
                    )
                }
            }
        }

        OverviewSectionCard(title = if (zh) "📈 信息熵分析 (加壳/混淆评估)" else "📈 Entropy analysis") {
            OverviewKv(if (zh) "前 64KB 熵" else "Head 64KB entropy", "%.3f".format(java.util.Locale.US, entropy.optDouble("head64k", 0.0)), mono = true, boldValue = true)
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    if (zh) "全局抽样熵" else "Global sample",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.weight(0.9f),
                )
                Text(
                    "%.3f".format(java.util.Locale.US, entropy.optDouble("globalSample", 0.0)),
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                StatusToneBadge(entropy.optString("level", "—"), entropy.optString("levelClass", "ok"))
            }
            EntropySparkline(values = bucketValues)
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(if (zh) "文件头 (0x0)" else "Head (0x0)", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text(if (zh) "文件尾" else "Tail", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Text(
                if (zh) {
                    "信息熵范围通常在 0 ~ 8，用于衡量二进制文件的无序度：\n• 4.0 ~ 6.0：常见普通未加密的结构化代码或明文数据。\n• 6.0 ~ 7.2：正常编译优化后的二进制文件（指令密集）。\n• 7.2 ~ 8.0：大概率使用了代码混淆、加固壳、强压缩或内部嵌有庞大的加密资源。"
                } else {
                    "Entropy is typically 0–8 and measures disorder:\n• 4.0–6.0: plain structured code/data\n• 6.0–7.2: normal optimized binaries\n• 7.2–8.0: likely packing/encryption/heavy obfuscation"
                },
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(10.dp))
                    .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.06f))
                    .padding(10.dp),
            )
        }

        OverviewSectionCard(title = if (zh) "🔗 依赖库（DT_NEEDED）说明" else "🔗 Needed libraries") {
            if (needed.length() == 0) {
                Text(
                    if (zh) "无依赖或无法解析" else "No dependencies or unresolved",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                for (i in 0 until needed.length()) {
                    val item = needed.optJSONObject(i) ?: continue
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .padding(vertical = 4.dp),
                        horizontalArrangement = Arrangement.spacedBy(10.dp),
                        verticalAlignment = Alignment.Top,
                    ) {
                        Text(
                            item.optString("name"),
                            modifier = Modifier.weight(1f),
                            style = MaterialTheme.typography.labelMedium,
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.primary,
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis,
                        )
                        Text(
                            item.optString("description"),
                            modifier = Modifier.weight(1.1f),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            textAlign = TextAlign.End,
                        )
                    }
                    if (i < needed.length() - 1) {
                        HorizontalDivider(thickness = 0.5.dp, color = MaterialTheme.colorScheme.outline.copy(alpha = 0.14f))
                    }
                }
            }
        }
    }
}

@Composable
private fun OverviewSectionCard(title: String, content: @Composable ColumnScope.() -> Unit) {
    Column(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.42f))
            .border(BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.14f)), RoundedCornerShape(14.dp))
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
        content = {
            Text(
                title,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurface,
                modifier = Modifier.padding(bottom = 4.dp),
            )
            HorizontalDivider(thickness = 0.6.dp, color = MaterialTheme.colorScheme.outline.copy(alpha = 0.18f))
            Spacer(Modifier.height(2.dp))
            content()
        },
    )
}

@Composable
private fun ReferenceOverviewCard(title: String, content: @Composable ColumnScope.() -> Unit) {
    Column(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(6.dp))
            .background(Color.White)
            .border(BorderStroke(1.dp, Color(0xFFEDF1F5)), RoundedCornerShape(6.dp))
            .padding(8.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Text(
            title,
            fontWeight = FontWeight.Bold,
            fontSize = 14.sp,
            color = Color(0xFF2F3B45),
            modifier = Modifier.padding(bottom = 4.dp),
        )
        HorizontalDivider(thickness = 1.dp, color = Color(0xFFEEEEEE))
        content()
    }
}

@Composable
private fun OverviewAlert(title: String, body: String) {
    Row(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(Color(0xFFFFF3CD))
            .border(BorderStroke(1.dp, Color(0xFFFFE08A)), RoundedCornerShape(12.dp))
            .padding(12.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text("⚠️", style = MaterialTheme.typography.titleMedium)
        Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(title, fontWeight = FontWeight.Bold, color = Color(0xFF664D03), style = MaterialTheme.typography.bodyMedium)
            Text(body, color = Color(0xFF664D03), style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun OverviewKv(
    label: String,
    value: String,
    mono: Boolean = false,
    boldValue: Boolean = false,
    maxLines: Int = 3,
    onClick: (() -> Unit)? = null,
) {
    Row(
        Modifier
            .fillMaxWidth()
            .then(if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier)
            .padding(vertical = 2.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.Top,
    ) {
        Text(
            label,
            modifier = Modifier.weight(0.85f),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            value.ifBlank { "—" },
            modifier = Modifier.weight(1.15f),
            style = MaterialTheme.typography.bodySmall,
            fontFamily = if (mono) FontFamily.Monospace else FontFamily.Default,
            fontWeight = if (boldValue) FontWeight.Bold else FontWeight.Medium,
            color = MaterialTheme.colorScheme.onSurface,
            maxLines = maxLines,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

@Composable
private fun OverviewMetric(
    label: String,
    value: String,
    modifier: Modifier = Modifier,
    accent: Color = MaterialTheme.colorScheme.primary,
) {
    Column(
        modifier
            .clip(RoundedCornerShape(10.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.42f))
            .padding(horizontal = 8.dp, vertical = 7.dp),
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1)
        Text(value, style = MaterialTheme.typography.labelMedium, color = accent, fontWeight = FontWeight.Bold, maxLines = 1, overflow = TextOverflow.Ellipsis)
    }
}

@Composable
private fun StatusToneBadge(text: String, tone: String, selected: Boolean = false) {
    val bg = toneColor(tone)
    val fg = if (tone == "warn") Color(0xFF1A1A1A) else Color.White
    Text(
        text,
        modifier = Modifier
            .clip(RoundedCornerShape(999.dp))
            .background(bg)
            .then(
                if (selected) {
                    Modifier.border(BorderStroke(1.5.dp, MaterialTheme.colorScheme.onSurface.copy(alpha = 0.55f)), RoundedCornerShape(999.dp))
                } else {
                    Modifier
                },
            )
            .padding(horizontal = 8.dp, vertical = 3.dp),
        color = fg,
        style = MaterialTheme.typography.labelSmall,
        fontWeight = FontWeight.SemiBold,
        maxLines = 1,
        overflow = TextOverflow.Ellipsis,
    )
}

@OptIn(androidx.compose.foundation.layout.ExperimentalLayoutApi::class)
@Composable
private fun SecurityFeatureCloud(
    security: org.json.JSONArray,
    selectedId: String?,
    onSelect: (String) -> Unit,
) {
    FlowRow(
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 4.dp, bottom = 2.dp),
    ) {
        for (i in 0 until security.length()) {
            val item = security.optJSONObject(i) ?: continue
            val id = item.optString("id", "item_$i")
            val label = item.optString("label")
            val tone = item.optString("tone", "ok")
            val selected = selectedId == id
            Box(
                Modifier
                    .clip(RoundedCornerShape(999.dp))
                    .clickable { onSelect(id) },
            ) {
                StatusToneBadge(label, tone, selected = selected)
            }
        }
    }
}

@Composable
private fun SecurityFeatureDetail(label: String, tone: String, description: String) {
    Column(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(toneColor(tone).copy(alpha = 0.10f))
            .border(BorderStroke(1.dp, toneColor(tone).copy(alpha = 0.28f)), RoundedCornerShape(12.dp))
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        StatusToneBadge(label, tone, selected = true)
        Text(
            description,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}

@Composable
private fun DifficultyHeader(score: String, level: String, cls: String, zh: Boolean) {
    val bg = toneColor(cls)
    val fg = if (cls == "warn") Color(0xFF1A1A1A) else Color.White
    Row(
        Modifier.padding(bottom = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Box(
            Modifier
                .size(80.dp)
                .clip(CircleShape)
                .background(bg),
            contentAlignment = Alignment.Center,
        ) {
            Text(score, color = fg, fontSize = 24.sp, fontWeight = FontWeight.Bold)
        }
        Column {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(if (zh) "逆向难度：" else "Difficulty: ", fontWeight = FontWeight.Bold, fontSize = 18.sp, color = Color(0xFF222222))
                StatusToneBadge(level, cls)
            }
            Text(
                if (zh) "评分范围 0-10，分值越高逆向难度越大" else "Score 0–10; higher means harder to reverse",
                modifier = Modifier.padding(top = 4.dp),
                fontSize = 12.sp,
                color = Color(0xFF666666),
            )
        }
    }
}

@Composable
private fun ReferenceReportLine(text: String, divider: Boolean) {
    Column(Modifier.fillMaxWidth()) {
        Text(text, fontSize = 12.sp, lineHeight = 22.sp, color = Color(0xFF444444), modifier = Modifier.padding(vertical = 2.dp))
        if (divider) HorizontalDivider(thickness = 0.5.dp, color = Color(0xFFF0F0F0))
    }
}

@Composable
private fun SectionTitleColored(text: String, color: Color) {
    Text(
        text,
        style = MaterialTheme.typography.labelLarge,
        fontWeight = FontWeight.Bold,
        color = color,
        modifier = Modifier.padding(top = 4.dp),
    )
}

@Composable
private fun FeasibilityFactorRow(title: String, detail: String, weight: Double, tone: String, zh: Boolean) {
    val color = toneColor(tone)
    Row(
        Modifier
            .fillMaxWidth()
            .border(BorderStroke(0.dp, Color.Transparent))
            .padding(vertical = 3.dp),
        horizontalArrangement = Arrangement.spacedBy(7.dp),
    ) {
        Box(Modifier.width(3.dp).height(32.dp).clip(RoundedCornerShape(2.dp)).background(color))
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(1.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text(
                title,
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Bold,
                color = color,
                modifier = Modifier.weight(1f),
            )
            if (weight > 0.0) {
                Text(
                    if (zh) "+${trimWeight(weight)}" else "+${trimWeight(weight)}",
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.Bold,
                    color = color,
                )
            }
            }
            if (detail.isNotBlank()) {
                Text(detail, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 2, overflow = TextOverflow.Ellipsis)
            }
        }
    }
}

@Composable
private fun FeasibilityRecommendRow(title: String, detail: String, tone: String) {
    val color = toneColor(tone)
    Row(
        Modifier
            .fillMaxWidth()
            .padding(vertical = 3.dp),
        horizontalArrangement = Arrangement.spacedBy(7.dp),
    ) {
        Box(Modifier.width(3.dp).height(32.dp).clip(RoundedCornerShape(2.dp)).background(color))
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(1.dp)) {
            Text(title, style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold, color = color)
            if (detail.isNotBlank()) {
                Text(detail, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 2, overflow = TextOverflow.Ellipsis)
            }
        }
    }
}

@Composable
private fun AttackSurfaceRow(title: String, value: String, detail: String, tone: String) {
    val color = toneColor(tone)
    Row(
        Modifier
            .fillMaxWidth()
            .padding(vertical = 3.dp),
        horizontalArrangement = Arrangement.spacedBy(7.dp),
    ) {
        Box(Modifier.width(3.dp).height(32.dp).clip(RoundedCornerShape(2.dp)).background(color))
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(1.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(title, style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold, color = color)
                if (value.isNotBlank()) {
                    Text(value, style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.onSurface)
                }
            }
            if (detail.isNotBlank()) {
                Text(detail, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 2, overflow = TextOverflow.Ellipsis)
            }
        }
    }
}

private fun toneColor(tone: String): Color = when (tone) {
    "danger" -> Color(0xFFDC3545)
    "warn" -> Color(0xFFFFC107)
    "info" -> Color(0xFF0B6BFF)
    else -> Color(0xFF28A745)
}

private fun trimWeight(weight: Double): String =
    if (weight == weight.toLong().toDouble()) weight.toLong().toString() else "%.1f".format(java.util.Locale.US, weight)

@Composable
private fun EntropySparkline(values: List<Double>) {
    val maxV = values.maxOrNull()?.coerceAtLeast(0.1) ?: 8.0
    Row(
        Modifier
            .fillMaxWidth()
            .height(60.dp)
            .clip(RoundedCornerShape(8.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f))
            .padding(horizontal = 4.dp, vertical = 6.dp),
        horizontalArrangement = Arrangement.spacedBy(1.dp),
        verticalAlignment = Alignment.Bottom,
    ) {
        if (values.isEmpty()) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text("—", color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        } else {
            values.forEach { v ->
                val ratio = (v / maxV).toFloat().coerceIn(0.04f, 1f)
                val color = when {
                    v >= 7.2 -> Color(0xFFDC3545)
                    v >= 6.0 -> Color(0xFFFFC107)
                    else -> Color(0xFF0B6BFF)
                }
                Box(
                    Modifier
                        .weight(1f)
                        .fillMaxHeight(ratio)
                        .clip(RoundedCornerShape(2.dp))
                        .background(color),
                )
            }
        }
    }
}

internal fun formatBytes(value: Long): String {
    if (value < 1024) return "${value}B"
    val kb = value / 1024.0
    if (kb < 1024) return "%.1fKB".format(Locale.US, kb)
    val mb = kb / 1024.0
    return "%.1fMB".format(Locale.US, mb)
}
