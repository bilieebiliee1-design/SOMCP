package com.soreverse.mcp

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.soreverse.mcp.core.DeepAnalysisService
import com.soreverse.mcp.core.SettingsStore
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject

internal data class RequestField(val key: String, val value: String)

internal fun parseRequestFields(raw: String): List<RequestField> {
    val json = runCatching { Json.parseToJsonElement(raw.ifBlank { "{}" }) as JsonObject }.getOrNull() ?: return emptyList()
    return json.map { (key, value) ->
        RequestField(key, if (value is JsonPrimitive && value !== JsonNull) value.content else value.toString())
    }
}

internal fun serializeRequestFields(fields: List<RequestField>, typedValues: Boolean): String {
    return buildJsonObject {
        fields.filter { it.key.isNotBlank() }.forEach { field ->
            val value = field.value.trim()
            val parsed = if (!typedValues) {
                JsonPrimitive(field.value)
            } else {
                when {
                    value.equals("null", true) -> JsonNull
                    value.equals("true", true) -> JsonPrimitive(true)
                    value.equals("false", true) -> JsonPrimitive(false)
                    value.toLongOrNull() != null -> JsonPrimitive(value.toLong())
                    value.toDoubleOrNull() != null -> JsonPrimitive(value.toDouble())
                    value.startsWith("{") -> runCatching { Json.parseToJsonElement(value) as JsonObject }.getOrElse { JsonPrimitive(field.value) }
                    value.startsWith("[") -> runCatching { Json.parseToJsonElement(value) as JsonArray }.getOrElse { JsonPrimitive(field.value) }
                    else -> JsonPrimitive(field.value)
                }
            }
            put(field.key.trim(), parsed)
        }
    }.toString()
}

@Composable
private fun RequestFieldsEditor(
    title: String,
    fields: List<RequestField>,
    keyHint: String,
    valueHint: String,
    emptyText: String,
    onChange: (List<RequestField>) -> Unit,
) {
    Column(Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text(title, Modifier.weight(1f), style = MaterialTheme.typography.labelLarge)
            TextButton(onClick = { onChange(fields + RequestField("", "")) }) { Text("+") }
        }
        if (fields.isEmpty()) {
            Text(emptyText, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        fields.forEachIndexed { index, field ->
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                OutlinedTextField(
                    value = field.key,
                    onValueChange = { next -> onChange(fields.toMutableList().also { it[index] = field.copy(key = next) }) },
                    label = { Text(keyHint) },
                    singleLine = true,
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.weight(0.9f),
                )
                Text(":", color = MaterialTheme.colorScheme.onSurfaceVariant)
                OutlinedTextField(
                    value = field.value,
                    onValueChange = { next -> onChange(fields.toMutableList().also { it[index] = field.copy(value = next) }) },
                    label = { Text(valueHint) },
                    singleLine = true,
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.weight(1.1f),
                )
                TextButton(onClick = { onChange(fields.filterIndexed { itemIndex, _ -> itemIndex != index }) }) { Text("−") }
            }
        }
    }
}

@Composable
internal fun SettingsAiDeepPage(t: UiText, settings: SettingsStore) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val deepService = remember { DeepAnalysisService(context.applicationContext) }
    var provider by remember { mutableStateOf(settings.aiProvider) }
    var endpoint by remember { mutableStateOf(settings.aiEndpoint) }
    var apiKey by remember { mutableStateOf(settings.aiApiKey) }
    var model by remember { mutableStateOf(settings.aiModel) }
    var temperature by remember { mutableStateOf(settings.aiTemperature.toString()) }
    var maxIterations by remember { mutableStateOf(settings.aiMaxIterations.toString()) }
    var historySoftLimit by remember { mutableStateOf(settings.aiHistorySoftLimit.toString()) }
    var headerFields by remember { mutableStateOf(parseRequestFields(settings.aiCustomHeadersJson)) }
    var bodyFields by remember { mutableStateOf(parseRequestFields(settings.aiCustomBodyJson)) }
    var systemPrompt by remember { mutableStateOf(settings.aiSystemPrompt) }
    var models by remember { mutableStateOf<List<String>>(emptyList()) }
    var modelQuery by remember { mutableStateOf("") }
    var status by remember { mutableStateOf("") }
    var loadingModels by remember { mutableStateOf(false) }

    PageScroll {
        GlassGroup(title = if (t.zh) "协议兼容" else "Provider") {
            ChipRow(
                listOf(
                    "openai" to "OpenAI",
                    "anthropic" to "Anthropic",
                ),
                provider,
            ) {
                provider = it
                settings.aiProvider = it
                if (it == "anthropic" && endpoint.contains("openai.com")) {
                    endpoint = "https://api.anthropic.com"
                    settings.aiEndpoint = endpoint
                } else if (it == "openai" && endpoint.contains("anthropic.com")) {
                    endpoint = "https://api.openai.com/v1"
                    settings.aiEndpoint = endpoint
                }
            }
        }
        GlassGroup(footer = if (t.zh) "兼容 OpenAI / Anthropic 及多数中转站。自定义 headers/body 用于服务商差异字段。" else "OpenAI/Anthropic compatible. Use custom headers/body for vendor-specific fields.") {
            OutlinedTextField(
                value = endpoint,
                onValueChange = { endpoint = it; settings.aiEndpoint = it },
                label = { Text(if (t.zh) "API 端点" else "API endpoint") },
                singleLine = true,
                shape = RoundedCornerShape(12.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = MaterialTheme.colorScheme.primary,
                    unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.35f),
                    focusedContainerColor = Color.Transparent,
                    unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
                ),
                modifier = Modifier.fillMaxWidth().padding(14.dp),
            )
            OutlinedTextField(
                value = apiKey,
                onValueChange = { apiKey = it; settings.aiApiKey = it },
                label = { Text("API Key") },
                singleLine = true,
                shape = RoundedCornerShape(12.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = MaterialTheme.colorScheme.primary,
                    unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.35f),
                    focusedContainerColor = Color.Transparent,
                    unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
                ),
                modifier = Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 4.dp),
            )
            OutlinedTextField(
                value = model,
                onValueChange = { model = it; settings.aiModel = it },
                label = { Text(if (t.zh) "模型" else "Model") },
                singleLine = true,
                shape = RoundedCornerShape(12.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = MaterialTheme.colorScheme.primary,
                    unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.35f),
                    focusedContainerColor = Color.Transparent,
                    unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
                ),
                modifier = Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 4.dp),
            )
            Column(
                verticalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.padding(14.dp),
            ) {
                PrimaryActionButton(
                    if (loadingModels) (if (t.zh) "获取中…" else "Loading…") else (if (t.zh) "自动获取模型" else "Fetch models"),
                    {
                        if (!loadingModels) {
                            loadingModels = true
                            status = if (t.zh) "正在拉取模型列表…" else "Fetching models…"
                            scope.launch {
                                val result = deepService.listModels(settings)
                                loadingModels = false
                                result.onSuccess {
                                    models = it
                                    status = if (t.zh) "已获取 ${it.size} 个模型" else "Fetched ${it.size} models"
                                }.onFailure {
                                    status = it.message ?: (if (t.zh) "获取模型失败" else "Failed to fetch models")
                                }
                            }
                        }
                    }, Modifier.fillMaxWidth(),
                )
                SecondaryActionButton(if (t.zh) "恢复默认提示词" else "Reset prompt", {
                    systemPrompt = SettingsStore.DEFAULT_AI_SYSTEM_PROMPT
                    settings.aiSystemPrompt = systemPrompt
                }, Modifier.fillMaxWidth())
            }
            if (status.isNotBlank()) {
                Text(status, modifier = Modifier.padding(horizontal = 14.dp, vertical = 4.dp), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            if (models.isNotEmpty()) {
                Text(if (t.zh) "可选模型" else "Available models", modifier = Modifier.padding(horizontal = 14.dp, vertical = 4.dp), style = MaterialTheme.typography.labelMedium)
                OutlinedTextField(
                    value = modelQuery,
                    onValueChange = { modelQuery = it },
                    label = { Text(if (t.zh) "搜索模型" else "Search models") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 4.dp),
                )
                val visibleModels = remember(models, modelQuery) {
                    models.asSequence()
                        .filter { modelQuery.isBlank() || it.contains(modelQuery, ignoreCase = true) }
                        .take(50)
                        .toList()
                }
                Column(Modifier.padding(horizontal = 14.dp, vertical = 4.dp)) {
                    visibleModels.forEachIndexed { index, candidate ->
                        Text(
                            candidate,
                            color = if (candidate == model) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface,
                            fontWeight = if (candidate == model) FontWeight.Bold else FontWeight.Normal,
                            style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    model = candidate
                                    settings.aiModel = candidate
                                }
                                .padding(vertical = 9.dp),
                        )
                        if (index < visibleModels.lastIndex) GroupDivider()
                    }
                    if (visibleModels.size == 50) {
                        Text(
                            if (t.zh) "仅显示前 50 项，请继续输入关键词缩小范围" else "Showing the first 50 results; refine your search",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(vertical = 8.dp),
                        )
                    }
                }
            }
        }
        GlassGroup(title = if (t.zh) "采样与深度" else "Sampling & depth") {
            DecimalSettingRow(
                label = "Temperature",
                value = temperature,
                suffix = "0–2",
                supporting = if (t.zh) "0.0 更稳定，数值越高输出越发散；常用范围 0.0–1.0。" else "0.0 is deterministic; higher values are more varied. Typical range: 0.0–1.0.",
                onValue = { temperature = it },
                onApply = {
                val v = it.coerceIn(0f, 2f)
                settings.aiTemperature = v
                temperature = v.toString()
            },
            )
            GroupDivider()
            NumberSettingRow(if (t.zh) "最大迭代" else "Max iterations", maxIterations, { maxIterations = it }, {
                settings.aiMaxIterations = it
                maxIterations = settings.aiMaxIterations.toString()
            }, if (t.zh) "轮" else "runs")
            GroupDivider()
            NumberSettingRow(if (t.zh) "历史压缩阈值" else "History soft limit", historySoftLimit, { historySoftLimit = it }, {
                settings.aiHistorySoftLimit = it
                historySoftLimit = settings.aiHistorySoftLimit.toString()
            }, if (t.zh) "条消息" else "msgs")
        }
        GlassGroup(
            title = if (t.zh) "自定义请求" else "Custom request",
            footer = if (t.zh) "同名字段覆盖默认请求，不同名字段增量加入。请求体会自动识别数字、布尔值、null、对象和数组。" else "Matching keys override defaults; new keys are appended. Body values detect numbers, booleans, null, objects, and arrays.",
        ) {
            RequestFieldsEditor(
                title = if (t.zh) "请求头" else "Headers",
                fields = headerFields,
                keyHint = if (t.zh) "键名" else "Key",
                valueHint = if (t.zh) "值" else "Value",
                emptyText = if (t.zh) "未添加自定义请求头" else "No custom headers",
            ) {
                headerFields = it
                settings.aiCustomHeadersJson = serializeRequestFields(it, false)
            }
            GroupDivider()
            RequestFieldsEditor(
                title = if (t.zh) "请求体字段" else "Body fields",
                fields = bodyFields,
                keyHint = if (t.zh) "键名" else "Key",
                valueHint = if (t.zh) "值" else "Value",
                emptyText = if (t.zh) "未添加自定义请求体字段" else "No custom body fields",
            ) {
                bodyFields = it
                settings.aiCustomBodyJson = serializeRequestFields(it, true)
            }
        }
        GlassGroup(title = if (t.zh) "深度逆向提示词" else "Deep analysis prompt") {
            OutlinedTextField(
                value = systemPrompt,
                onValueChange = { systemPrompt = it; settings.aiSystemPrompt = it },
                label = { Text(if (t.zh) "系统提示词" else "System prompt") },
                minLines = 8,
                shape = RoundedCornerShape(12.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = MaterialTheme.colorScheme.primary,
                    unfocusedBorderColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.35f),
                    focusedContainerColor = Color.Transparent,
                    unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
                ),
                modifier = Modifier.fillMaxWidth().padding(14.dp),
            )
        }
    }
}
