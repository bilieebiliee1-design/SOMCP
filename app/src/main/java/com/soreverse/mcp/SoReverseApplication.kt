package com.soreverse.mcp

import android.app.Application
import com.soreverse.mcp.core.AppLog
import com.soreverse.mcp.core.CrashReporter
import com.soreverse.mcp.core.IntegrityGuard
import com.soreverse.mcp.core.SettingsStore
import com.soreverse.mcp.core.ToolStats
import com.soreverse.mcp.nativecore.RizinNativeEngine

class SoReverseApplication : Application() {
    /**
     * Early integrity enforcement. Signature-bypass frameworks such as SigKill,
     * TweakMe and SignatureKiller install their PackageManager hook inside
     * attachBaseContext(), so their trick is already active before onCreate().
     * Running our native filesystem-level signer check at this same point
     * catches a repackaged / re-signed APK at the earliest possible moment.
     * Any exception is swallowed so a legitimate start is unaffected.
     */
    override fun attachBaseContext(base: Context) {
        runCatching { IntegrityGuard.enforceEarly(base) }
        super.attachBaseContext(base)
    }

    override fun onCreate() {
        super.onCreate()
        if (CrashReporter.isCrashProcess()) return
        AppLog.init(this)
        CrashReporter.install(this)
        val settings = SettingsStore(this)
        ToolStats.setPersistEnabled(settings.toolStatsPersist)
        ToolStats.attachContext(this)
        RizinNativeEngine.configureGhidra(this)
        IntegrityGuard.enforce(this)
        AppLog.i("SOMCP initialized (toolStatsPersist=${settings.toolStatsPersist})")
    }
}
