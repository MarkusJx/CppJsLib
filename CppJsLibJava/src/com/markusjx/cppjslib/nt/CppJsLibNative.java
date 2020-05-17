/*
 * CppJsLibNative.java
 *
 * Licensed under the MIT License
 *
 * Copyright (c) 2020 MarkusJx
 *
 * The full license including third-party licenses is available at https://github.com/MarkusJx/CppJsLib/blob/master/LICENSE
 */
package com.markusjx.cppjslib.nt;

import com.markusjx.cppjslib.CppJsLib;
import com.markusjx.cppjslib.interfaces.CExposedFunc;
import com.markusjx.cppjslib.interfaces.CExposedVoidFunc;
import com.markusjx.cppjslib.interfaces.Handler;
import com.markusjx.cppjslib.interfaces.LoggingFunction;

/**
 * Native functions. Do not call
 * @hidden Do not use
 */
public final class CppJsLibNative {
    static {
        System.loadLibrary("CppJsLib");

        CppJsLib.init();
    }

    public static native int initWebGUI(String base_dir);

    public static native int initWebGUI(String base_dir, String cert_path, String private_key_path, int websocket_fallback_plain);

    public static native boolean running(int id);

    public static native boolean stopped(int id);

    public static native void checkPorts(int id, boolean val);

    public static native boolean checkPorts(int id);

    public static native void setLogger(int id, LoggingFunction loggingFunction);

    public static native void setError(int id, LoggingFunction errorFunction);

    public static native void setLogger(LoggingFunction loggingFunction);

    public static native void setError(LoggingFunction errorFunction);

    public static native void setWebSocketOpenHandler(int id, Handler handler);

    public static native void setWebSocketCloseHandler(int id, Handler handler);

    public static native boolean start(int id, int port, int websocketPort, String host, boolean block);

    public static native boolean startNoWeb(int id, int port, String host, boolean block);

    public static native boolean startNoWebSocket(int id, int port, String host, boolean block);

    public static native void setMountPoint(int id, String mnt, String dir);

    public static native void removeMountPoint(int id, String mnt);

    public static native boolean stop(int id, boolean block, int maxWaitSeconds);

    public static native void exposeFunction(int id, CExposedFunc f, String name, String returnType, String[] argTypes);

    public static native void exposeVoidFunction(int id, CExposedVoidFunc f, String name, String[] argTypes);

    public static native int importFunction(int id, String name, String returnType, String[] argTypes, int wait);

    public static native String[] callJSFunction(int clsID, int id, String[] args);

    public static native void callVoidJsFunction(int cldID, int id, String[] args);

    public static native String stringArrayToJSON(String[] arr);

    public static native String[] createStringArrayFromJSON(String json);

    public static native void deleteWebGUI(int id);

    public static native boolean hasWebsocketSupport();

    public static native boolean hasHttpsSupport();

    public static native boolean ok();

    public static native String getLastError();

    public static native void resetLastError();
}
