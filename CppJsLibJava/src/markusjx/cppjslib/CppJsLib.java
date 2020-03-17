package markusjx.cppjslib;

import markusjx.cppjslib.interfaces.LoggingFunction;
import markusjx.cppjslib.nt.CppJsLibNative;

public class CppJsLib {
    public static boolean ok() {
        return CppJsLibNative.ok();
    }

    public static String getLastError() {
        return CppJsLibNative.getLastError();
    }

    public static void resetLastError() {
        CppJsLibNative.resetLastError();
    }

    public static void setLogger(LoggingFunction loggingFunction) {
        CppJsLibNative.setLogger(loggingFunction);
    }

    public static void setError(LoggingFunction errorFunction) {
        CppJsLibNative.setError(errorFunction);
    }
}
