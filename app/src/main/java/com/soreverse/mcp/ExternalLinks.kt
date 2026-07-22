package com.soreverse.mcp

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.widget.Toast

internal fun joinQqGroup(context: Context, zh: Boolean) {
    val uris = listOf(
        "mqqapi://card/show_pslcard?src_type=internal&version=1&uin=1079912856&card_type=group&source=qrcode",
        "tencent://groupwpa/?subcmd=all&uin=1079912856",
        "mqqwpa://im/chat?chat_type=group&uin=1079912856&version=1&src_type=web",
    )
    val packages = listOf(null, "com.tencent.mobileqq", "com.tencent.tim")
    for (uri in uris) {
        for (pkg in packages) {
            val intent = Intent(Intent.ACTION_VIEW, Uri.parse(uri)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
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
        context.packageManager.getLaunchIntentForPackage(pkg)?.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)?.let { launcher ->
            runCatching {
                context.startActivity(launcher)
                Toast.makeText(context, if (zh) "已打开 QQ/TIM，请手动搜索群号 1079912856" else "Opened QQ/TIM. Search group 1079912856 manually.", Toast.LENGTH_LONG).show()
                return
            }
        }
    }
    Toast.makeText(context, if (zh) "无法唤起 QQ/TIM，请确认已安装并允许打开应用链接" else "Cannot open QQ/TIM. Check installation and app-link handling.", Toast.LENGTH_SHORT).show()
}
