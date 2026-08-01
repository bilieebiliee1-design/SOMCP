package com.soreverse.mcp.core

import com.soreverse.mcp.core.AppLog
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.ConcurrentHashMap

/**
 * Manages multiple APK MCP bridge instances.
 * Each bridge configuration (URL + token) is handled by one ApkBridgeInstance.
 * Provides aggregated tool listing and tool call routing across all bridges.
 */
class ApkBridgeManager(private val settings: SettingsStore) {

    private val bridges = ConcurrentHashMap<String, ApkBridgeInstance>()

    /**
     * Rebuild bridge instances from current settings.
     * Call this when bridge configurations change.
     */
    @Synchronized
    fun refreshFromSettings() {
        val configs = settings.apkBridgeConfigs
        val configIds = configs.map { it.id }.toSet()

        // Remove bridges that are no longer in config
        val toRemove = bridges.keys.filter { it !in configIds }
        toRemove.forEach { id ->
            bridges.remove(id)?.let {
                it.stopHealthMonitor()
                AppLog.i("apk-mcp bridge removed: ${it.config.label}")
            }
        }

        // Add or update bridges
        configs.forEach { config ->
            val existing = bridges[config.id]
            if (existing == null) {
                // Create new bridge instance
                val instance = ApkBridgeInstance(config, settings)
                bridges[config.id] = instance
                if (config.enabled && config.url.isNotBlank()) {
                    instance.startHealthMonitor()
                }
                AppLog.i("apk-mcp bridge added: ${config.label}")
            } else if (existing.config != config) {
                // Config changed - rebuild instance
                existing.stopHealthMonitor()
                val newInstance = ApkBridgeInstance(config, settings)
                bridges[config.id] = newInstance
                if (config.enabled && config.url.isNotBlank()) {
                    newInstance.startHealthMonitor()
                }
                AppLog.i("apk-mcp bridge updated: ${config.label}")
            }
        }
    }

    /**
     * Find the bridge instance responsible for the given tool name.
     */
    fun bridgeForTool(toolName: String): ApkBridgeInstance? {
        return bridges.values.find { it.isBridgedTool(toolName) && it.state().online }
    }

    /**
     * Get all online bridge instances.
     */
    fun allOnlineBridges(): List<ApkBridgeInstance> {
        return bridges.values.filter { it.state().online }
    }

    /**
     * Get all bridge instances (online and offline).
     */
    fun allBridges(): List<ApkBridgeInstance> {
        return bridges.values.toList()
    }

    /**
     * Aggregate tools from all online bridges.
     */
    fun aggregatedTools(): List<ApkBridgeInstance.ToolDef> {
        return allOnlineBridges().flatMap { it.mergedTools() }
    }

    /**
     * Probe all bridges.
     */
    fun probeAll() {
        bridges.values.forEach { it.probe() }
    }

    /**
     * Start health monitoring for all enabled bridges.
     */
    fun startAllHealthMonitors() {
        bridges.values.forEach { instance ->
            if (instance.config.enabled && instance.config.url.isNotBlank()) {
                instance.startHealthMonitor()
            }
        }
    }

    /**
     * Stop all health monitors.
     */
    fun stopAllHealthMonitors() {
        bridges.values.forEach { it.stopHealthMonitor() }
    }

    /**
     * Get a specific bridge by ID.
     */
    fun bridge(id: String): ApkBridgeInstance? = bridges[id]

    /**
     * Snapshot JSON for all bridges.
     */
    fun snapshotJson(): JSONObject {
        val arr = JSONArray()
        bridges.values.forEach { arr.put(it.snapshotJson()) }
        return JSONObject()
            .put("bridges", arr)
            .put("count", bridges.size)
            .put("onlineCount", allOnlineBridges().size)
    }
}
