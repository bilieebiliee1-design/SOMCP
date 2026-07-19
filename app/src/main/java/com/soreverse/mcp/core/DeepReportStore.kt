package com.soreverse.mcp.core

import android.content.Context
import org.json.JSONObject
import java.io.File

object DeepReportStore {
    private const val FILE_NAME = "local-ai-reports.json"

    fun save(context: Context, workspaceId: String, snapshot: JSONObject) {
        if (workspaceId.isBlank()) return
        synchronized(this) {
            val root = readRoot(context)
            root.put(workspaceId, snapshot)
            writeRoot(context, root)
        }
    }

    fun load(context: Context, workspaceId: String): JSONObject? = synchronized(this) {
        readRoot(context).optJSONObject(workspaceId)
    }

    fun ids(context: Context): Set<String> = synchronized(this) {
        val root = readRoot(context)
        buildSet {
            val keys = root.keys()
            while (keys.hasNext()) add(keys.next())
        }
    }

    fun remove(context: Context, workspaceId: String) {
        synchronized(this) {
            val root = readRoot(context)
            root.remove(workspaceId)
            writeRoot(context, root)
        }
    }

    private fun readRoot(context: Context): JSONObject = runCatching {
        JSONObject(File(context.filesDir, FILE_NAME).readText())
    }.getOrDefault(JSONObject())

    private fun writeRoot(context: Context, root: JSONObject) {
        val target = File(context.filesDir, FILE_NAME)
        val temporary = File(context.filesDir, "$FILE_NAME.tmp")
        temporary.writeText(root.toString())
        if (!temporary.renameTo(target)) {
            target.writeText(root.toString())
            temporary.delete()
        }
    }
}
