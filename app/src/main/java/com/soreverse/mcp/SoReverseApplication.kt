package com.soreverse.mcp

import android.app.Application
import com.soreverse.mcp.core.AppLog
import com.soreverse.mcp.core.CrashReporter
import com.soreverse.mcp.core.IntegrityGuard
import com.soreverse.mcp.core.SettingsStore
import com.soreverse.mcp.core.ToolStats
import com.soreverse.mcp.nativecore.RizinNativeEngine

class SoReverseApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        if (CrashReporter.isCrashProcess()) return
        AppLog.init(this)
        CrashReporter.install(this)
        val settings = SettingsStore(this)
        ToolStats.setPersistEnabled(settings.toolStatsPersist)
        ToolStats.attachContext(this)
        RizinNativeEngine.configureGhidra(this)
        val integrity = IntegrityGuard.verify(this)
        if (!integrity.trusted) AppLog.e("Integrity check failed: ${integrity.reason}; expected=${integrity.expected}; actual=${integrity.actual.joinToString()}")
        AppLog.i("SOMCP initialized (toolStatsPersist=${settings.toolStatsPersist})")
    }
}
