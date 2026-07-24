package com.soreverse.mcp

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast

internal fun copy(context: Context, text: String, copiedText: String) {
    (context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager).setPrimaryClip(ClipData.newPlainText("MCP URL", text))
    Toast.makeText(context, copiedText, Toast.LENGTH_SHORT).show()
}
