package com.markusjx.cppjslib;

import com.markusjx.cppjslib.interfaces.LoggingFunction;
import com.markusjx.cppjslib.nt.CppJsLibNative;

/**
 * The CppJsLib super class
 */
@SuppressWarnings("unused")
public class CppJsLib {
    /**
     * Init. Do not call.
     */
    public static void init() {
        hasHttpsSupport = CppJsLibNative.hasHttpsSupport();
        hasWebsocketSupport = CppJsLibNative.hasWebsocketSupport();
    }

    /**
     * Is true if the C++ library was built with websocket protocol support
     */
    private static boolean hasWebsocketSupport;

    /**
     * Is true if the C++ library was built with HTTPS support
     */
    private static boolean hasHttpsSupport;

    /**
     * Get if the C++ library was built with websocket protocol support
     *
     * @return true, if the C++ library was built with websocket protocol support
     */
    public static boolean hasWebsocketSupport() {
        return hasWebsocketSupport;
    }

    /**
     * Get if the C++ library was built with HTTPS support
     *
     * @return true, if the C++ library was built with HTTPS support
     */
    public static boolean hasHttpsSupport() {
        return hasHttpsSupport;
    }

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
