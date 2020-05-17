/*
 * CppJsLib.java
 *
 * Licensed under the MIT License
 *
 * Copyright (c) 2020 MarkusJx
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * The full license including third-party licenses is available at https://github.com/MarkusJx/CppJsLib/blob/master/LICENSE
 */
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
