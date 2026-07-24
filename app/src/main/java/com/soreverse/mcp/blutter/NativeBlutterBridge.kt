package com.soreverse.mcp.blutter

internal object NativeBlutterBridge {
    private val available = runCatching { System.loadLibrary("blutter_bridge"); true }.getOrDefault(false)

    fun run(libraryName: String, libappFd: Int, libflutterFd: Int, resultFd: Int, optionsJson: String, cancellationToken: Long): Int {
        check(available) { "Blutter native bridge is unavailable" }
        return nativeRun(libraryName, libappFd, libflutterFd, resultFd, optionsJson, cancellationToken)
    }

    fun cancel(cancellationToken: Long) {
        if (available) nativeCancel(cancellationToken)
    }

    private external fun nativeRun(libraryName: String, libappFd: Int, libflutterFd: Int, resultFd: Int, optionsJson: String, cancellationToken: Long): Int
    private external fun nativeCancel(cancellationToken: Long)
}
