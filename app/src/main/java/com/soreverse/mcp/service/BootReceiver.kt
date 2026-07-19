package com.soreverse.mcp.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.soreverse.mcp.core.AppLog
import com.soreverse.mcp.core.IntegrityGuard
import com.soreverse.mcp.core.SettingsStore

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != Intent.ACTION_BOOT_COMPLETED &&
            intent?.action != "android.intent.action.QUICKBOOT_POWERON" &&
            intent?.action != "com.htc.intent.action.QUICKBOOT_POWERON"
        ) return
        if (!IntegrityGuard.isTrusted(context.applicationContext)) {
            AppLog.e("Boot autostart blocked by integrity guard")
            return
        }
        val settings = SettingsStore(context)
        if (!settings.bootAutoStart) {
            AppLog.i("Boot completed: bootAutoStart is off, skipping autostart")
            return
        }
        try {
            McpForegroundService.start(context)
            AppLog.i("Boot completed: started McpForegroundService (bootAutoStart=on)")
        } catch (e: Exception) {
            AppLog.e("Boot autostart failed", e)
        }
    }
}
