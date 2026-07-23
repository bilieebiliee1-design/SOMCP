package com.soreverse.mcp.blutter;

import android.os.ParcelFileDescriptor;
import com.soreverse.mcp.blutter.IBlutterRunnerCallback;

interface IBlutterRunner {
    String getManifestJson();
    void run(String jobId, String libraryName, in ParcelFileDescriptor libapp, in ParcelFileDescriptor libflutter, in ParcelFileDescriptor result, String optionsJson, IBlutterRunnerCallback callback);
    void cancel(String jobId);
}
