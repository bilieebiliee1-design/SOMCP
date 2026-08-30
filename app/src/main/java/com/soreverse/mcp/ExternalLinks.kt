/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (C) 2026 bilieebiliee1-design
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

package com.soreverse.mcp

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.activity.result.ActivityResultLauncher
import com.soreverse.mcp.core.AppLog

/**
 * Safely launches the SAF directory-tree picker ([Intent.ACTION_OPEN_DOCUMENT_TREE]).
 *
 * Some OEM builds (e.g. EMUI/HarmonyOS on Huawei) ship without any app that can
 * handle this action, and pointing a plain `ActivityResultLauncher` at it would then
 * throw [ActivityNotFoundException]. This helper guards the launch in a try/catch and
 * surfaces a Toast instead of crashing.
 *
 * IMPORTANT: the launch is NOT pre-gated on `intent.resolveActivity()`. On several OEM
 * ROMs (OnePlus/ColorOS, some MIUI builds) the resolver reports no handler for
 * `ACTION_OPEN_DOCUMENT_TREE` through `resolveActivity()` even though a working SAF
 * document provider is installed and `startActivityForResult` succeeds. Gating the
 * launch on that (unreliable) check produced the false "无 SAF 文件提供方 / no folder
 * picker" error on otherwise healthy devices. We launch directly and only surface the
 * helper message when the system genuinely throws [ActivityNotFoundException].
 */
internal fun launchSafTreePicker(context: Context, zh: Boolean, launcher: ActivityResultLauncher<Uri?>) {
    try {
        launcher.launch(null)
    } catch (_: ActivityNotFoundException) {
        AppLog.w("ACTION_OPEN_DOCUMENT_TREE not handled; SAF folder picker unavailable.")
        Toast.makeText(
            context,
            if (zh) {
                "当前设备没有可用的文件夹选择器（无 SAF 文件提供方）。请在系统设置中安装或启用文件管理器后重试。"
            } else {
                "No folder picker available on this device (no SAF document provider). Install or enable a file manager and retry."
            },
            Toast.LENGTH_LONG
        ).show()
    }
}

internal fun joinQqGroup(context: Context, zh: Boolean) {
    val uris = listOf(
        "mqqapi://card/show_pslcard?src_type=internal&version=1&uin=1079912856&card_type=group&source=qrcode",
        "tencent://groupwpa/?subcmd=all&uin=1079912856",
        "mqqwpa://im/chat?chat_type=group&uin=1079912856&version=1&src_type=web"
    )
    val packages = listOf(null, "com.tencent.mobileqq", "com.tencent.tim")
    for (uri in uris) {
        for (pkg in packages) {
            val intent = Intent(
                Intent.ACTION_VIEW,
                Uri.parse(uri)
            ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            if (pkg != null) intent.setPackage(pkg)
            runCatching {
                context.startActivity(intent)
                return
            }
        }
    }
    for (pkg in listOf("com.tencent.mobileqq", "com.tencent.tim")) {
        for (uri in uris) {
            val intent = Intent(Intent.ACTION_VIEW, Uri.parse(uri))
                .setClassName(pkg, "com.tencent.mobileqq.activity.JumpActivity")
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            runCatching {
                context.startActivity(intent)
                return
            }
        }
        context.packageManager.getLaunchIntentForPackage(
            pkg
        )?.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)?.let { launcher ->
            runCatching {
                context.startActivity(launcher)
                Toast.makeText(
                    context,
                    if (zh) "已打开 QQ/TIM，请手动搜索群号 1079912856" else "Opened QQ/TIM. Search group 1079912856 manually.",
                    Toast.LENGTH_LONG
                ).show()
                return
            }
        }
    }
    Toast.makeText(
        context,
        if (zh) "无法唤起 QQ/TIM，请确认已安装并允许打开应用链接" else "Cannot open QQ/TIM. Check installation and app-link handling.",
        Toast.LENGTH_SHORT
    ).show()
}
