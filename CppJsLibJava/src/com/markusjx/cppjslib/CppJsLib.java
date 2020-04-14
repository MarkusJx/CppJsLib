package com.markusjx.cppjslib;

import com.markusjx.cppjslib.interfaces.LoggingFunction;
import com.markusjx.cppjslib.nt.CppJsLibNative;

/**
 * The CppJsLib super class
 */
@SuppressWarnings("unused")
public class CppJsLib {
    /**
     * Check if there was an error
     *
     * @return true, if there was no error
     */
    public static boolean ok() {
        return CppJsLibNative.ok();
    }

    /**
     * Gets the last error string
     *
     * @return the error string
     */
    public static String getLastError() {
        return CppJsLibNative.getLastError();
    }

    /**
     * Reset the last error (If read and non-fatal)
     */
    public static void resetLastError() {
        CppJsLibNative.resetLastError();
    }

    /**
     * Set a global logger for all future instances of {@link WebGUI}.
     * Does not work for existing instances. In this case, use {@link WebGUI#setLogger(LoggingFunction)}
     *
     * @param loggingFunction a {@link LoggingFunction} to be called
     */
    public static void setLogger(LoggingFunction loggingFunction) {
        CppJsLibNative.setLogger(loggingFunction);
    }

    /**
     * Set a global error handler for all future instances of {@link WebGUI}.
     * Does not work for existing instances. In this case, use {@link WebGUI#setLogger(LoggingFunction)}
     *
     * @param errorFunction a {@link LoggingFunction} to be called
     */
    public static void setError(LoggingFunction errorFunction) {
        CppJsLibNative.setError(errorFunction);
    }
}
