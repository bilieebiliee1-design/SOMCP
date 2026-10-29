plugins {
    id("com.android.application") version "9.2.1" apply false
    id("org.jetbrains.kotlin.android") version "2.4.0" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.4.0" apply false
}

// SDK / namespace 集中在这里，:app 直接引用（同一次构建里读到的是同一份值）。
//
// 这三个值也是 CNB 镜像预热工程读取的那份（image/cnb-tools.Dockerfile →
// scripts/cnb/warmup-project.sh）：预热工程的 :app 只剩 plugins {}，AGP 建
// 模块级模型要的 namespace / compileSdk / minSdk 从这里取，读不到就让镜像
// 构建失败 —— 宁可早失败，也不要预热成一套 SDK 版本、运行期用另一套。
// rootProject.extra：从 :app 的脚本里读得到，不用再引一份 buildSrc。
extra["somcpNamespace"] = "com.soreverse.mcp"
extra["somcpCompileSdk"] = 36
extra["somcpMinSdk"] = 26
