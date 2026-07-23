package com.soreverse.mcp.blutter;

interface IBlutterRunnerCallback {
    void onProgress(String jobId, String stage, int percent);
    void onCompleted(String jobId, int exitCode, String errorCode, String message, long resultBytes, String resultSha256);
}
