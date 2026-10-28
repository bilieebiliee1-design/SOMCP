/*
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * SOMCP - buildSrc/src/main/kotlin/SomcpPatchedLocalJarsPlugin.kt
 * Copyright (C) 2026 SOMCP authors
 * Upstream: https://github.com/bilieebiliee1-design/SOMCP
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License version 3 as published by
 * the Free Software Foundation.
 */

import org.gradle.api.DefaultTask
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.provider.MapProperty
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.kotlin.dsl.register

/**
 * 把 app/libs/ 下的 patched jar 发布成「带 module 元数据」的依赖，替代
 * `implementation(files("libs/xxx-patched.jar"))`。
 *
 * files() 的依赖不参与冲突检测：Gradle 不知道它与 Maven 上的
 * com.github.zhkl0228:unidbg-api / capstone / keystone 是同一个模块，而 Maven 上
 * 那几份会经 unidbg-api 的 POM 传递依赖自动进来，于是同一个包被两份 jar 提供：
 *
 *   Duplicate class com.github.unidbg.AbstractEmulator found in modules
 *     unidbg-api-0.9.9-android-patched.jar and com.github.zhkl0228.unidbg:unidbg-api:0.9.9
 *   2 files found with path 'android/sdk23/system/usr/share/zoneinfo/tzdata'
 *
 * 发布成模块之后 Gradle 才能按默认的 newest 冲突策略挑掉 Maven 上那份。本地这份
 * 的版本号与上游**完全相同** —— 补丁针对的就是那个版本，取代关系只对它成立；
 * 两边同版本时谁赢取决于仓库顺序，所以 settings.gradle.kts 的
 * `somcpPatchedLocalJars` 必须排在 google() / mavenCentral() 之前，CNB 的
 * init script 还要把它提到所有镜像最前。
 *
 * 元数据里必须显式给出「这是给 Android 用的 jar」这几个属性，否则 AGP 的变体
 * 匹配认不出它和上游是同一个模块（上游只有 POM，没有 .module 文件）。
 */
class SomcpPatchedLocalJarsPlugin : Plugin<Project> {
    override fun apply(target: Project) = with(target) {
        val repoDir = rootDir.toPath()
            .resolve("buildSrc/build/patched-jar-repository")
            .toFile()

        val generate = tasks.register<PatchedJarMetadata>("generatePatchedJarRepository") {
            description = "Publishes app/libs/patched jars with module metadata so Gradle can de-duplicate them."
            jars.from(
                rootProject.layout.projectDirectory.dir("app/libs").asFileTree.matching { include("*-patched.jar") },
            )
            entries.set(
                objects.mapProperty(String::class.java, String::class.java).also { map ->
                    PATCHED_JARS.forEach { (coordinate, jarAndVersion) ->
                        map.put(coordinate, "${jarAndVersion.first}|${jarAndVersion.second}")
                    }
                },
            )
            outputDir.set(repoDir)
        }

        // 仓库目录必须在**任何依赖解析之前**就有内容：settings.gradle.kts 里那个
        // 本地仓库按目录内容找坐标，而 AGP 的变体匹配、IDE 同步、依赖报告都可能
        // 发生在配置期。产物写进 buildSrc/build，与任务的 @OutputDirectory 一致，
        // 后续任务因此是 UP-TO-DATE，不会重复执行。代价只有两次 jar 复制。
        afterEvaluate { generate.get().generate() }

        // 解析发生在 task 执行期时，靠这两条保证顺序。
        listOf("preBuild", "classes", "test").forEach { taskName ->
            tasks.named { it == taskName }.configureEach { dependsOn(generate) }
        }
    }

    companion object {
        /** <group>:<module> -> (jar 文件名, 版本) */
        private val PATCHED_JARS = mapOf(
            "com.github.zhkl0228:unidbg-api" to ("unidbg-api-0.9.9-android-patched.jar" to "0.9.9"),
            "com.github.zhkl0228:unidbg-android" to ("unidbg-android-0.9.9-android-patched.jar" to "0.9.9"),
            "com.github.zhkl0228:capstone" to ("capstone-3.1.8-android-patched.jar" to "3.1.8"),
            "com.github.zhkl0228:keystone" to ("keystone-0.9.7-android-patched.jar" to "0.9.7"),
        )
    }
}

/** 生成带 .module 元数据的本地 Maven 仓库布局。 */
abstract class PatchedJarMetadata : DefaultTask() {
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val jars: ConfigurableFileCollection

    /** "<group>:<module>" -> "<jar 文件名>|<版本>" */
    @get:Input
    abstract val entries: MapProperty<String, String>

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @TaskAction
    fun generate() {
        val out = outputDir.get().asFile
        out.deleteRecursively()
        out.mkdirs()
        entries.get().forEach { (coordinate, value) ->
            val (jarName, version) = value.split("|")
            val jar = jars.files.firstOrNull { it.name == jarName }
                ?: throw IllegalStateException(
                    "patched jar '$jarName' is missing; it must stay committed under app/libs/ " +
                        "because no CI build can produce it",
                )
            val (group, module) = coordinate.split(":")
            val versionDir = out.resolve("${group.replace('.', '/')}/$module/$version")
            versionDir.mkdirs()
            val published = "$module-$version.jar"
            jar.copyTo(versionDir.resolve(published), overwrite = true)
            versionDir.resolve("$module-$version.module").writeText(metadata(group, module, version, published))
        }
    }

    private fun attrs(usage: String) = listOf(
        "\"org.gradle.category\": \"library\"",
        "\"org.gradle.dependency.bundling\": \"external\"",
        "\"org.gradle.jvm.environment\": \"android\"",
        "\"org.gradle.libraryelements\": \"jar\"",
        "\"org.gradle.status\": \"release\"",
        "\"org.gradle.usage\": \"$usage\"",
    ).joinToString(",\n              ")

    private fun metadata(group: String, module: String, version: String, jarName: String) = """
        {
          "formatVersion": "1.1",
          "component": {
            "group": "$group",
            "module": "$module",
            "version": "$version",
            "attributes": {
              ${attrs("java-api")}
            }
          },
          "variants": [
            {
              "name": "apiElements",
              "attributes": {
                ${attrs("java-api")}
              },
              "files": [ { "name": "${'$'}{jarName}", "url": "${'$'}{jarName}" } ]
            },
            {
              "name": "runtimeElements",
              "attributes": {
                ${attrs("java-runtime")}
              },
              "files": [ { "name": "${'$'}{jarName}", "url": "${'$'}{jarName}" } ]
            }
          ]
        }
    """.trimIndent() + "\n"
}
