package xx.gusss.ksu.magica;

import android.app.ZygotePreload;
import android.content.pm.ApplicationInfo;
import android.util.Log;

import androidx.annotation.NonNull;

import java.io.File;

public class AppPreload implements ZygotePreload {
    public static final String TAG = "Magica";

    private static native void forkDontCareAndExecKsud(String ksudPath, String packageName);

    @Override
    public void doPreload(@NonNull ApplicationInfo appInfo) {
        File f = new File(appInfo.nativeLibraryDir, "libdaemon.so");
        try {
            System.loadLibrary("kernelsu");
            Log.d(TAG, "executing magica ...");
            forkDontCareAndExecKsud(f.getAbsolutePath(), appInfo.packageName);
        } catch (Throwable t) {
            Log.e(TAG, "failed to late load", t);
        }
    }
}
