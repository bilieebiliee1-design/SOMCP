package com.soreverse.mcp.core

import kotlinx.coroutines.suspendCancellableCoroutine
import okhttp3.Call
import okhttp3.Callback
import okhttp3.Response
import java.io.IOException

internal suspend fun Call.await(): Response = suspendCancellableCoroutine { continuation ->
    continuation.invokeOnCancellation { cancel() }
    enqueue(object : Callback {
        override fun onFailure(call: Call, error: IOException) {
            if (continuation.isActive) continuation.resumeWith(Result.failure(error))
        }

        override fun onResponse(call: Call, response: Response) {
            if (continuation.isActive) {
                continuation.resumeWith(Result.success(response))
            } else {
                response.close()
            }
        }
    })
}
