package com.soreverse.mcp.core

import android.content.Context
import com.soreverse.mcp.engine.NativeSoEngine

object EngineProvider {
    @Volatile private var engine: NativeSoEngine? = null

    fun get(context: Context): NativeSoEngine {
        return engine ?: synchronized(this) {
            engine ?: NativeSoEngine(context.applicationContext).also { engine = it }
        }
    }

    fun restoreWorkDirectory(context: Context) {
        SettingsStore(context.applicationContext).treeUri?.let { uri ->
            runCatching { get(context).setWorkDirectory(uri) }
                .onFailure { AppLog.e("Failed to restore work directory", it) }
        }
    }
}
