package com.soreverse.mcp

import android.app.Application
import com.soreverse.mcp.BuildConfig
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
        if (!integrity.trusted) {
            AppLog.e("Integrity check FAILED: ${integrity.reason}; expected=${integrity.expected}; actual=${integrity.actual.joinToString()}; threats=${integrity.threats.joinToString()}")
            // Terminate on release builds — prevents tampered app from running
            // In debug builds, allow running for development convenience
            if (!BuildConfig.DEBUG) {
                IntegrityGuard.terminateProcess()
            }
        } else {
            AppLog.i("Integrity check passed: ${integrity.reason}")
        }
        AppLog.i("SOMCP initialized (toolStatsPersist=${settings.toolStatsPersist})")
    }
}
