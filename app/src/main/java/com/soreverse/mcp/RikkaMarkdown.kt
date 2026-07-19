package com.soreverse.mcp

import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.LinkAnnotation
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.withLink
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.mapLatest
import org.intellij.markdown.flavours.gfm.GFMFlavourDescriptor
import org.intellij.markdown.flavours.gfm.GFMElementTypes
import org.intellij.markdown.flavours.gfm.GFMTokenTypes
import org.intellij.markdown.ast.ASTNode
import org.intellij.markdown.MarkdownElementTypes
import org.intellij.markdown.MarkdownTokenTypes
import org.intellij.markdown.html.HtmlGenerator
import org.intellij.markdown.parser.MarkdownParser
import org.jsoup.Jsoup
import org.jsoup.nodes.Element
import org.jsoup.nodes.Node
import org.jsoup.nodes.TextNode

private val markdownFlavour by lazy {
    GFMFlavourDescriptor(makeHttpsAutoLinks = true, useSafeLinks = true)
}

private val markdownParser by lazy { MarkdownParser(markdownFlavour) }

private data class MarkdownParseResult(val content: String, val ast: ASTNode, val html: String)

private fun ASTNode.containsHtml(): Boolean =
    type == MarkdownElementTypes.HTML_BLOCK || type == MarkdownTokenTypes.HTML_TAG || children.any { it.containsHtml() }

private fun parseMarkdown(content: String): MarkdownParseResult {
    val tree = markdownParser.buildMarkdownTreeFromString(content)
    return MarkdownParseResult(
        content,
        tree,
        HtmlGenerator(content, tree, markdownFlavour).generateHtml(),
    )
}

@Composable
@OptIn(ExperimentalCoroutinesApi::class)
internal fun RikkaMarkdown(
    content: String,
    modifier: Modifier = Modifier,
    selectable: Boolean = true,
) {
    var parsed by remember { mutableStateOf(parseMarkdown(content)) }
    val updatedContent by rememberUpdatedState(content)
    LaunchedEffect(Unit) {
        snapshotFlow { updatedContent }
            .distinctUntilChanged()
            .mapLatest(::parseMarkdown)
            .catch { }
            .flowOn(Dispatchers.Default)
            .collect { parsed = it }
    }
    val body: @Composable () -> Unit = {
        Column(modifier, verticalArrangement = Arrangement.spacedBy(6.dp)) {
            val document = remember(parsed.html) { Jsoup.parse(parsed.html) }
            document.body().childNodes().forEach { MarkdownNode(it) }
        }
    }
    if (selectable) SelectionContainer(content = body) else body()
}

private fun ASTNode.text(content: String): String = content.substring(startOffset, endOffset)

@Composable
private fun MarkdownAstNode(node: ASTNode, content: String) {
    when (node.type) {
        MarkdownElementTypes.PARAGRAPH -> Text(inlineText(node, content), style = MaterialTheme.typography.bodyMedium, lineHeight = 24.sp)
        MarkdownElementTypes.ATX_1, MarkdownElementTypes.ATX_2, MarkdownElementTypes.ATX_3,
        MarkdownElementTypes.ATX_4, MarkdownElementTypes.ATX_5, MarkdownElementTypes.ATX_6 -> {
            val level = when (node.type) {
                MarkdownElementTypes.ATX_1 -> 1; MarkdownElementTypes.ATX_2 -> 2; MarkdownElementTypes.ATX_3 -> 3
                MarkdownElementTypes.ATX_4 -> 4; MarkdownElementTypes.ATX_5 -> 5; else -> 6
            }
            val headingText = inlineText(node, content).let { value ->
                val start = value.indexOfFirst { !it.isWhitespace() && it != '#' }.coerceAtLeast(0)
                val end = value.indexOfLast { !it.isWhitespace() && it != '#' }.let { if (it < start) value.length else it + 1 }
                value.subSequence(start, end)
            }
            Text(
                headingText,
                fontSize = when (level) { 1 -> 24.sp; 2 -> 22.sp; 3 -> 20.sp; 4 -> 18.sp; 5 -> 16.sp; else -> 14.sp },
                lineHeight = when (level) { 1 -> 30.sp; 2 -> 27.5.sp; 3 -> 25.sp; 4 -> 22.5.sp; 5 -> 20.sp; else -> 17.5.sp },
                fontWeight = FontWeight.Bold,
                modifier = Modifier.padding(vertical = when (level) { 1 -> 16.dp; 2 -> 14.dp; 3 -> 12.dp; 4 -> 10.dp; 5 -> 8.dp; else -> 6.dp }),
            )
        }
        MarkdownElementTypes.UNORDERED_LIST, MarkdownElementTypes.ORDERED_LIST -> {
            val ordered = node.type == MarkdownElementTypes.ORDERED_LIST
            Column(verticalArrangement = Arrangement.spacedBy(5.dp)) {
                node.children.filter { it.type == MarkdownElementTypes.LIST_ITEM }.forEachIndexed { index, item ->
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(if (ordered) "${index + 1}." else "•", color = MaterialTheme.colorScheme.primary)
                        Text(item.text(content).trim().trimStart('-', '*', '+').trim(), Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
                    }
                }
            }
        }
        MarkdownElementTypes.BLOCK_QUOTE -> Row(
            Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.2f)).padding(8.dp),
        ) {
            Text(node.text(content).trimStart('>', ' '), fontStyle = FontStyle.Italic, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        MarkdownElementTypes.CODE_FENCE -> {
            val raw = node.text(content)
            val lines = raw.lines()
            val code = lines.drop(1).dropLast(if (lines.lastOrNull()?.trimStart()?.startsWith("```") == true) 1 else 0).joinToString("\n")
            CodeSurface(code)
        }
        MarkdownElementTypes.CODE_BLOCK -> CodeSurface(node.text(content))
        GFMElementTypes.TABLE -> MarkdownAstTable(node, content)
        MarkdownTokenTypes.HORIZONTAL_RULE -> HorizontalDivider(Modifier.padding(vertical = 16.dp), color = MaterialTheme.colorScheme.primary.copy(alpha = 0.5f), thickness = 0.5.dp)
        else -> node.children.forEach { MarkdownAstNode(it, content) }
    }
}

@Composable
private fun CodeSurface(code: String) {
    Surface(Modifier.fillMaxWidth(), shape = RoundedCornerShape(10.dp), color = MaterialTheme.colorScheme.surfaceContainerHigh) {
        Text(code, fontFamily = FontFamily.Monospace, fontSize = 13.sp, lineHeight = 20.sp, modifier = Modifier.horizontalScroll(rememberScrollState()).padding(14.dp))
    }
}

private fun inlineText(node: ASTNode, content: String) = buildAnnotatedString {
    fun appendNode(current: ASTNode) {
        when (current.type) {
            MarkdownElementTypes.STRONG -> withStyle(SpanStyle(fontWeight = FontWeight.Bold)) { current.children.forEach(::appendNode) }
            MarkdownElementTypes.EMPH -> withStyle(SpanStyle(fontStyle = FontStyle.Italic)) { current.children.forEach(::appendNode) }
            GFMElementTypes.STRIKETHROUGH -> withStyle(SpanStyle(textDecoration = TextDecoration.LineThrough)) { current.children.forEach(::appendNode) }
            MarkdownElementTypes.CODE_SPAN -> withStyle(SpanStyle(fontFamily = FontFamily.Monospace)) { append(current.text(content).trim('`')) }
            MarkdownTokenTypes.TEXT, MarkdownTokenTypes.WHITE_SPACE, MarkdownTokenTypes.EOL -> append(current.text(content))
            else -> if (current.children.isEmpty()) {
                val value = current.text(content)
                if (current.type != MarkdownTokenTypes.ATX_HEADER && current.type != MarkdownTokenTypes.LIST_BULLET) append(value)
            } else current.children.forEach(::appendNode)
        }
    }
    appendNode(node)
}

@Composable
private fun MarkdownAstTable(node: ASTNode, content: String) {
    val rows = node.children.filter { it.type == GFMElementTypes.HEADER || it.type == GFMElementTypes.ROW }
    Column(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).clip(RoundedCornerShape(8.dp)).background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f))) {
        rows.forEachIndexed { rowIndex, row ->
            Row(Modifier.padding(horizontal = 10.dp, vertical = 8.dp), horizontalArrangement = Arrangement.spacedBy(18.dp)) {
                row.children.filter { it.type == GFMTokenTypes.CELL }.forEach { cell ->
                    Text(cell.text(content).trim().trim('|', ' '), fontWeight = if (rowIndex == 0) FontWeight.Bold else FontWeight.Normal, style = MaterialTheme.typography.bodySmall)
                }
            }
            if (rowIndex < rows.lastIndex) HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
        }
    }
}

@Composable
private fun MarkdownNode(node: Node) {
    when (node) {
        is Element -> MarkdownElement(node)
        is TextNode -> node.text().trim().takeIf(String::isNotEmpty)?.let {
            Text(it, style = MaterialTheme.typography.bodyMedium, lineHeight = 24.sp)
        }
    }
}

@Composable
private fun MarkdownElement(element: Element) {
    when (element.tagName()) {
        "h1", "h2", "h3", "h4", "h5", "h6" -> {
            val level = element.tagName().drop(1).toIntOrNull() ?: 3
            Text(
                inlineHtml(element),
                fontSize = when (level) {
                    1 -> 24.sp
                    2 -> 21.sp
                    3 -> 18.sp
                    else -> 16.sp
                },
                fontWeight = FontWeight.Bold,
                modifier = Modifier.padding(top = if (level <= 2) 10.dp else 6.dp, bottom = 2.dp),
            )
        }
        "p" -> Text(inlineHtml(element), style = MaterialTheme.typography.bodyMedium, lineHeight = 24.sp)
        "pre" -> {
            val code = element.selectFirst("code")?.wholeText() ?: element.wholeText()
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(10.dp),
                color = MaterialTheme.colorScheme.surfaceContainerHigh,
            ) {
                Text(
                    code,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 13.sp,
                    lineHeight = 20.sp,
                    modifier = Modifier.horizontalScroll(rememberScrollState()).padding(14.dp),
                )
            }
        }
        "blockquote" -> Row(
            Modifier.fillMaxWidth().clip(RoundedCornerShape(4.dp)).background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f)).padding(start = 4.dp),
        ) {
            Column(Modifier.fillMaxWidth().padding(start = 10.dp, top = 10.dp, end = 12.dp, bottom = 10.dp)) {
                element.childNodes().forEach { MarkdownNode(it) }
            }
        }
        "ul", "ol" -> Column(verticalArrangement = Arrangement.spacedBy(5.dp)) {
            element.children().filter { it.tagName() == "li" }.forEachIndexed { index, item ->
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(if (element.tagName() == "ol") "${index + 1}." else "•", color = MaterialTheme.colorScheme.primary)
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(5.dp)) {
                        val nested = item.children().filter { it.tagName() == "ul" || it.tagName() == "ol" }
                        val own = item.clone().apply { select("ul,ol").remove() }
                        Text(inlineHtml(own), style = MaterialTheme.typography.bodyMedium, lineHeight = 24.sp)
                        nested.forEach { MarkdownElement(it) }
                    }
                }
            }
        }
        "table" -> MarkdownTable(element)
        "hr" -> HorizontalDivider(Modifier.padding(vertical = 8.dp), color = MaterialTheme.colorScheme.outlineVariant)
        else -> if (element.children().isEmpty()) {
            Text(inlineHtml(element), style = MaterialTheme.typography.bodyMedium, lineHeight = 24.sp)
        } else {
            element.childNodes().forEach { MarkdownNode(it) }
        }
    }
}

private fun inlineHtml(element: Element) = buildAnnotatedString {
    fun appendNode(node: Node) {
        when (node) {
            is TextNode -> append(node.wholeText)
            is Element -> when (node.tagName().lowercase()) {
                "strong", "b" -> withStyle(SpanStyle(fontWeight = FontWeight.Bold)) { node.childNodes().forEach(::appendNode) }
                "em", "i" -> withStyle(SpanStyle(fontStyle = FontStyle.Italic)) { node.childNodes().forEach(::appendNode) }
                "del", "s", "strike" -> withStyle(SpanStyle(textDecoration = TextDecoration.LineThrough)) { node.childNodes().forEach(::appendNode) }
                "code" -> withStyle(
                    SpanStyle(
                        fontFamily = FontFamily.Monospace,
                        background = Color(0x1A808080),
                    ),
                ) { node.childNodes().forEach(::appendNode) }
                "a" -> {
                    val href = node.attr("href")
                    if (href.isNotBlank()) {
                        withLink(LinkAnnotation.Url(href)) {
                            withStyle(
                                SpanStyle(
                                    color = Color(0xFF007AFF),
                                    textDecoration = TextDecoration.Underline,
                                ),
                            ) { node.childNodes().forEach(::appendNode) }
                        }
                    } else {
                        node.childNodes().forEach(::appendNode)
                    }
                }
                "br" -> append('\n')
                else -> node.childNodes().forEach(::appendNode)
            }
        }
    }
    element.childNodes().forEach(::appendNode)
}

@Composable
private fun MarkdownTable(table: Element) {
    val rows = table.select("tr")
    Column(
        Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).clip(RoundedCornerShape(8.dp)).background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f)),
    ) {
        rows.forEachIndexed { rowIndex, row ->
            Row(Modifier.padding(horizontal = 10.dp, vertical = 8.dp), horizontalArrangement = Arrangement.spacedBy(18.dp)) {
                row.select("th,td").forEach { cell ->
                    Text(
                        cell.text(),
                        fontWeight = if (rowIndex == 0 || cell.tagName() == "th") FontWeight.Bold else FontWeight.Normal,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
            if (rowIndex < rows.lastIndex) HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
        }
    }
}
