/*
 * WebGUI.java
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

import com.markusjx.cppjslib.exception.CppOutOfMemoryException;
import com.markusjx.cppjslib.exception.ObjectAlreadyDeletedException;
import com.markusjx.cppjslib.exception.OperationNotSupportedException;
import com.markusjx.cppjslib.exception.PortAlreadyInUseException;
import com.markusjx.cppjslib.functional.ExposedFunction;
import com.markusjx.cppjslib.functional.ExposedVoidFunction;
import com.markusjx.cppjslib.interfaces.*;
import com.markusjx.cppjslib.nt.CppJsLibNative;
import com.markusjx.cppjslib.util.utils;

import java.io.IOException;
import java.lang.ref.Cleaner;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.ServerSocket;

/**
 * The main WebGUI class
 * Example:
 * <pre>{@code
 *      public class Example {
 *          // Add @Expose to expose function. Remove the '/'. This is just here for formatting
 *          /@Expose
 *          public static void fn1(int i) {
 *              // Code
 *          }
 *
 *          public static void fn2(String s) {
 *              // Code
 *          }
 *
 *          public static void main(String[] args) throws CppJsLibException {
 *              // Create instance of WebGUI
 *              WebGUI gui = new WebGUI("web");
 *
 *              // Expose all functions in this class
 *              gui.exposeAll(Example.class);
 *
 *              // Manually expose a function, cast all types, enter argument types
 *              gui.exposeVoidFunction(args1 -> fn2((String) args1[0]), "fn2", String.class);
 *
 *              // Import javascript void function with name and argument types
 *              var fn = gui.importVoidFunction("func", int.class);
 *
 *              // Import non-void function with name, a timeout, -1 equals infinite,
 *              // the return type and the argument types
 *              var f = gui.importFunction("f", -1, int.class, int.class);
 *
 *              // Start the servers with their ports on this machine, without blocking
 *              gui.start(8025, 8026, "localhost", false);
 *
 *              // Stop the servers
 *              gui.stop();
 *
 *              // Close all resources
 *              gui.close();
 *          }
 *      }
 * }</pre>
 * <p>
 * IMPORTANT: call {@link #close()} when finished with this object
 * <br>
 * <br>
 * If the C++ library was built without HTTPS support, following functions will throw an {@link OperationNotSupportedException}:
 * {@link #WebGUI(String, String, String)}, {@link #WebGUI(String, String, String, int)}
 * <br>
 * <br>
 * If the C++ library was built without websocket protocol support, following functions will throw an {@link OperationNotSupportedException}:
 * {@link #start(int, int, String)}, {@link #start(int, int, String, boolean)}, {@link #startNoWeb(int, String)}, {@link #startNoWeb(int, String, boolean)}, {@link #WebGUI(String, String, String, int)},
 * {@link #setWebSocketOpenHandler(Handler)}, {@link #setWebSocketCloseHandler(Handler)}, {@link #importVoidFunction(String, Class[])}, {@link #importFunction(String, int, Class, Class[])}
 * <br>
 * <br>
 * Do not call any function after {@link #close()} has been called. Otherwise an {@link ObjectAlreadyDeletedException} will be thrown.
 */
@SuppressWarnings("unused")
public class WebGUI implements AutoCloseable {
    /**
     * A cleaner
     */
    private static final Cleaner cleaner = Cleaner.create();
    /**
     * The id of this instance
     */
    private final int id;
    /**
     * A cleanable
     */
    private final Cleaner.Cleanable cleanable;
    /**
     * If C++ should check for used ports
     */
    private boolean CCheckPorts;
    /**
     * If ports should be checked, if they are in use
     */
    private boolean checkPorts;
    /**
     * If the underlying WebGUI instance has been deleted
     */
    private boolean deleted;

    /**
     * Create a WebGUI instance without a base directory.
     * May only be used to start without a http(s) server ({@link #startNoWeb(int, String)}, {@link #startNoWeb(int, String, boolean)})
     *
     * @throws CppOutOfMemoryException if not enough memory is available
     */
    public WebGUI() throws CppOutOfMemoryException {
        id = CppJsLibNative.initWebGUI("");
        checkWebGUIAlloc(id);

        this.cleanable = cleaner.register(this, this::delete);

        CCheckPorts = false;
        checkPorts = true;
        deleted = false;
        CppJsLibNative.checkPorts(id, false);
    }

    /**
     * Create a WebGUI instance
     *
     * @param base_dir the base directory
     * @throws CppOutOfMemoryException if not enough memory is available
     */
    public WebGUI(String base_dir) throws CppOutOfMemoryException {
        id = CppJsLibNative.initWebGUI(base_dir);
        checkWebGUIAlloc(id);

        this.cleanable = cleaner.register(this, this::delete);

        CCheckPorts = false;
        checkPorts = true;
        deleted = false;
        CppJsLibNative.checkPorts(id, false);
    }

    /**
     * Create a WebGUI instance with SSL/TLS enabled.
     * This will throw an {@link OperationNotSupportedException} if the C++ library was built without HTTPS support
     *
     * @param base_dir         the base directory
     * @param cert_path        the certificate path
     * @param private_key_path the private key path
     * @throws CppOutOfMemoryException if not enough memory is available
     */
    public WebGUI(String base_dir, String cert_path, String private_key_path) throws CppOutOfMemoryException {
        if (!CppJsLib.hasHttpsSupport()) {
            try {
                throw new OperationNotSupportedException("CppJsLib was built without HTTPS support");
            } catch (OperationNotSupportedException e) {
                throw new RuntimeException(e);
            }
        }

        id = CppJsLibNative.initWebGUI(base_dir, cert_path, private_key_path, 0);
        checkWebGUIAlloc(id);

        this.cleanable = cleaner.register(this, this::delete);

        CCheckPorts = false;
        checkPorts = true;
        deleted = false;
        CppJsLibNative.checkPorts(id, false);
    }

    /**
     * Create a WebGUI instance with SSL/TLS enabled.
     * This will throw an {@link OperationNotSupportedException} if the C++ library was built without HTTPS support.
     * This will throw an {@link OperationNotSupportedException} if the C++ library was built without websocket protocol support
     *
     * @param base_dir                 the base directory
     * @param cert_path                the certificate path
     * @param private_key_path         the private key path
     * @param websocket_fallback_plain a websocket fallback port, if encryption did fail
     * @throws CppOutOfMemoryException if not enough memory is available
     */
    public WebGUI(String base_dir, String cert_path, String private_key_path, int websocket_fallback_plain) throws CppOutOfMemoryException {
        if (!CppJsLib.hasWebsocketSupport()) {
            try {
                throw new OperationNotSupportedException("CppJsLib was built without websocket protocol support. Cannot set ws fallback port");
                // Well, technically it can, this would not be an issue, but it does not make any sense
            } catch (OperationNotSupportedException e) {
                throw new RuntimeException(e);
            }
        }

        if (!CppJsLib.hasHttpsSupport()) {
            try {
                throw new OperationNotSupportedException("CppJsLib was built without HTTPS support");
            } catch (OperationNotSupportedException e) {
                throw new RuntimeException(e);
            }
        }

        id = CppJsLibNative.initWebGUI(base_dir, cert_path, private_key_path, websocket_fallback_plain);
        checkWebGUIAlloc(id);

        this.cleanable = cleaner.register(this, this::delete);

        CCheckPorts = false;
        checkPorts = true;
        deleted = false;
        CppJsLibNative.checkPorts(id, false);
    }

    /**
     * Check the WebGUI memory allocation status
     *
     * @param id the new id
     * @throws CppOutOfMemoryException if not enough memory is available
     */
    private void checkWebGUIAlloc(int id) throws CppOutOfMemoryException {
        if (id == -1) {
            throw new CppOutOfMemoryException("Could not allocate WebGUI: Out of memory");
        }
    }

    /**
     * Check if ports are in use
     *
     * @param address the host address
     * @param ports   the ports to check
     * @return if any port of {@code ports} are in use
     */
    private boolean portsInUse(String address, int... ports) {
        for (int p : ports) {
            try {
                ServerSocket ss = new ServerSocket(p, 50, InetAddress.getByName(address));
                ss.close();
            } catch (IOException e) {
                return true;
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return false;
    }

    /**
     * Check if the servers are running
     *
     * @return true, if the servers are running
     */
    public boolean isRunning() {
        checkDeleted();
        return CppJsLibNative.running(id);
    }

    /**
     * Check if the servers are stopped
     *
     * @return true, if the servers are stopped
     */
    public boolean stopped() {
        checkDeleted();
        return CppJsLibNative.stopped(id);
    }

    /**
     * Sets if the application should check if any ports are in use
     *
     * @param val check if the ports are in use
     */
    public void checkPorts(boolean val) {
        checkDeleted();
        if (CCheckPorts) {
            CppJsLibNative.checkPorts(id, val);
        } else {
            checkPorts = val;
        }
    }

    /**
     * Returns if the application checks if any ports are in use
     *
     * @return true, if the application checks if any ports are in use
     */
    public boolean checkPorts() {
        checkDeleted();
        if (CCheckPorts) {
            return CppJsLibNative.checkPorts(id);
        } else {
            return checkPorts;
        }
    }

    /**
     * Get if Java or C++ checks if any ports are in use
     *
     * @return true, if C++ checks
     */
    public boolean getCCheckPorts() {
        return CCheckPorts;
    }

    /**
     * Set if Java or C++ checks if any ports are in use
     *
     * @param val if C++ should check
     */
    public void setCCheckPorts(boolean val) {
        checkDeleted();
        CCheckPorts = val;
        if (val) {
            CppJsLibNative.checkPorts(id, checkPorts);
        }
    }

    /**
     * Set a logger
     *
     * @param loggingFunction a {@link LoggingFunction} to log
     */
    public void setLogger(LoggingFunction loggingFunction) {
        checkDeleted();
        CppJsLibNative.setLogger(id, loggingFunction);
    }

    /**
     * Set an error logger
     *
     * @param errorFunction a {@link LoggingFunction} to log errors
     */
    public void setError(LoggingFunction errorFunction) {
        checkDeleted();
        CppJsLibNative.setError(id, errorFunction);
    }

    /**
     * Set a handler which triggers if a client connects to a websocket port.
     * This will throw an {@link OperationNotSupportedException} if the C++ library was built without websocket protocol support
     *
     * @param handler the handler to be called
     */
    public void setWebSocketOpenHandler(Handler handler) {
        checkDeleted();
        if (!CppJsLib.hasWebsocketSupport()) {
            try {
                throw new OperationNotSupportedException("CppJsLib was built without websocket protocol support");
            } catch (OperationNotSupportedException e) {
                throw new RuntimeException(e);
            }
        }

        CppJsLibNative.setWebSocketOpenHandler(id, handler);
    }

    /**
     * Set a handler which triggers if a client disconnects from a websocket port.
     * This will throw an {@link OperationNotSupportedException} if the C++ library was built without websocket protocol support
     *
     * @param handler the handler to be called
     */
    public void setWebSocketCloseHandler(Handler handler) {
        checkDeleted();
        if (!CppJsLib.hasWebsocketSupport()) {
            try {
                throw new OperationNotSupportedException("CppJsLib was built without websocket protocol support");
            } catch (OperationNotSupportedException e) {
                throw new RuntimeException(e);
            }
        }

        CppJsLibNative.setWebSocketCloseHandler(id, handler);
    }

    /**
     * Start all servers. Blocking call.
     * This will throw an {@link OperationNotSupportedException} if the C++ library was built without websocket protocol support
     *
     * @param port          the port of the http server
     * @param websocketPort the port of the websocket server
     * @param host          the host address
     * @return if the operation was successful
     * @throws PortAlreadyInUseException if one of the requested ports is already in use
     */
    public boolean start(int port, int websocketPort, String host) throws PortAlreadyInUseException {
        return start(port, websocketPort, host, true);
    }

    /**
     * @param port the port of the http server
     * @param host the host address
     * @return if the operation was successful
     * @throws PortAlreadyInUseException if one of the requested ports is already in use
     */
    public boolean start(int port, String host) throws PortAlreadyInUseException {
        return start(port, host, true);
    }

    /**
     * @param port  the port of the http server
     * @param host  the host address
     * @param block if the operation was successful
     * @return if the operation was successful
     * @throws PortAlreadyInUseException if one of the requested ports is already in use
     */
    public boolean start(int port, String host, boolean block) throws PortAlreadyInUseException {
        checkDeleted();
        if (CppJsLib.hasWebsocketSupport()) {
            try {
                throw new OperationNotSupportedException("CppJsLib was built with websocket protocol support, websocket port is required");
            } catch (OperationNotSupportedException e) {
                throw new RuntimeException(e);
            }
        }

        if (!CCheckPorts && checkPorts && portsInUse(host, port)) {
            throw new PortAlreadyInUseException("A requested port was already in use");
        } else {
            return CppJsLibNative.start(id, port, 0, host, block);
        }
    }

    /**
     * Start all servers.
     * This will throw an {@link OperationNotSupportedException} if the C++ library was built without websocket protocol support
     *
     * @param port          the port if the http server
     * @param websocketPort the port of the websocket server
     * @param host          the host address
     * @param block         if this is a blocking call
     * @return if the operation was successful. (Returns false or...blocks)
     * @throws PortAlreadyInUseException if one of the requested ports is already in use
     */
    public boolean start(int port, int websocketPort, String host, boolean block) throws PortAlreadyInUseException {
        checkDeleted();
        if (!CppJsLib.hasWebsocketSupport()) {
            try {
                throw new OperationNotSupportedException("CppJsLib was built without websocket protocol support");
            } catch (OperationNotSupportedException e) {
                throw new RuntimeException(e);
            }
        }

        if (!CCheckPorts && checkPorts && portsInUse(host, port, websocketPort)) {
            throw new PortAlreadyInUseException("A requested port was already in use");
        } else {
            return CppJsLibNative.start(id, port, websocketPort, host, block);
        }
    }

    /**
     * Start only the websocket servers. Blocking call.
     * This will throw an {@link OperationNotSupportedException} if the C++ library was built without websocket protocol support
     *
     * @param port the port to listen on
     * @param host the host address
     * @return if the operation was successful. (Can only return false. Really. Blocks otherwise.)
     * @throws PortAlreadyInUseException if one of the requested ports is already in use
     */
    public boolean startNoWeb(int port, String host) throws PortAlreadyInUseException {
        return startNoWeb(port, host, true);
    }

    /**
     * Start only the websocket servers.
     * This will throw an {@link OperationNotSupportedException} if the C++ library was built without websocket protocol support
     *
     * @param port  the port to listen on
     * @param block if this is a blocking call
     * @return if the operation was successful
     * @throws PortAlreadyInUseException if one of the requested ports is already in use
     */
    public boolean startNoWeb(int port, String host, boolean block) throws PortAlreadyInUseException {
        checkDeleted();
        if (!CppJsLib.hasWebsocketSupport()) {
            try {
                throw new OperationNotSupportedException("CppJsLib was built without websocket protocol support");
            } catch (OperationNotSupportedException e) {
                throw new RuntimeException(e);
            }
        }

        if (!CCheckPorts && checkPorts && portsInUse("localhost", port)) {
            throw new PortAlreadyInUseException("A requested port was already in use");
        } else {
            return CppJsLibNative.startNoWeb(id, port, host, block);
        }
    }

    /**
     * Start only the http server.
     *
     * @param port  the port to listen on
     * @param block if this is a blocking call
     * @return if the operation was successful
     * @throws PortAlreadyInUseException if one of the requested ports is already in use
     */
    public boolean startNoWebSocket(int port, String host, boolean block) throws PortAlreadyInUseException {
        checkDeleted();

        if (!CCheckPorts && checkPorts && portsInUse("localhost", port)) {
            throw new PortAlreadyInUseException("A requested port was already in use");
        } else {
            return CppJsLibNative.startNoWebSocket(id, port, host, block);
        }
    }

    /**
     * Set a mount point. Read more at the http server doc
     *
     * @param mnt the mount point
     * @param dir the directory path to mount
     * @see <a href="https://github.com/yhirose/cpp-httplib#static-file-server">yhirose/cpp-httplib</a>
     */
    public void setMountPoint(String mnt, String dir) {
        checkDeleted();
        CppJsLibNative.setMountPoint(id, mnt, dir);
    }

    /**
     * Remove a mount point. Read more at the http server doc
     *
     * @param mnt the mount point to remove
     * @see <a href="https://github.com/yhirose/cpp-httplib#static-file-server">yhirose/cpp-httplib</a>
     */
    public void removeMountPoint(String mnt) {
        checkDeleted();
        CppJsLibNative.removeMountPoint(id, mnt);
    }

    /**
     * Stop all servers. Blocking call
     *
     * @return if the operation was successful. Can only return true or block indefinitely
     */
    public boolean stop() {
        checkDeleted();
        return CppJsLibNative.stop(id, true, -1);
    }

    /**
     * Stop all servers
     *
     * @param block if this is a blocking call, if this is true, it will block indefinitely. Or till it finishes. But then you should use {@link #stop()}
     * @return if the operation was successful
     * @deprecated You should wait for the operation to finish and use {@link #stop()} instead
     */
    @Deprecated
    public boolean stop(boolean block) {
        return stop(block, -1);
    }

    /**
     * Stop all servers
     *
     * @param block          if this is a blocking call
     * @param maxWaitSeconds a timout, if it is a blocking call, if not, use {@link #stop(boolean)}
     * @return if the operation was successful
     * @deprecated You should wait for the operation to finish and use {@link #stop()} instead
     */
    @Deprecated
    public boolean stop(boolean block, int maxWaitSeconds) {
        checkDeleted();
        return CppJsLibNative.stop(id, block, maxWaitSeconds);
    }

    /**
     * Expose all functions inside a class with a given class object
     *
     * @param cls the class containing the functions. The functions must be annotated with {@link Expose}
     * @param obj a class object to call the (non-static) functions from
     */
    public void exposeAll(Class<?> cls, Object obj) {
        checkDeleted();
        for (Method m : cls.getMethods()) {
            if (m.isAnnotationPresent(Expose.class)) {
                String name = m.getName();
                if (!m.getAnnotation(Expose.class).name().isEmpty()) {
                    name = m.getAnnotation(Expose.class).name();
                }

                System.out.println("Exposing function: " + name);
                if (m.getReturnType().equals(Void.TYPE)) {
                    exposeVoidFunction(args -> {
                        try {
                            m.invoke(obj, args);
                        } catch (IllegalAccessException | InvocationTargetException e) {
                            e.printStackTrace();
                        }
                    }, name, m.getParameterTypes());
                } else {
                    exposeFunction(args -> {
                        try {
                            return m.invoke(obj, args);
                        } catch (IllegalAccessException | InvocationTargetException e) {
                            e.printStackTrace();
                            return null;
                        }
                    }, name, m.getReturnType(), m.getParameterTypes());
                }
            }
        }
    }

    /**
     * Expose all functions inside a class
     *
     * @param obj a class object to call the (non-static) functions from
     */
    public void exposeAll(Object obj) {
        exposeAll(obj.getClass(), obj);
    }

    /**
     * Expose all functions inside a class
     *
     * @param cls the class containing (static) the functions. The functions must be annotated with {@link Expose}
     */
    public void exposeAll(Class<?> cls) {
        exposeAll(cls, null);
    }

    /**
     * Expose a non-void function to JavaScript
     *
     * @param func         the {@link ExposedFunc} to expose
     * @param functionName the name of the function to expose. Or any name to identify it in js
     * @param returnType   the return type class
     * @param types        the type classes of all arguments
     * @param <R>          the return type
     */
    public <R> void exposeFunction(ExposedFunc func, String functionName, Class<R> returnType, Class<?>... types) {
        checkDeleted();
        ExposedFunction<R> exposedFunction = new ExposedFunction<>(func, functionName, returnType, types);
        CppJsLibNative.exposeFunction(id, exposedFunction.getFunc(), exposedFunction.getName(), exposedFunction.getReturnType(), exposedFunction.getArgTypes());
    }

    /**
     * Expose a void function to JavaScript
     *
     * @param func         the {@link ExposedVoidFunc} to expose
     * @param functionName the name of the function to expose. Or any name to identify it in js
     * @param types        the type classes of all arguments
     */
    public void exposeVoidFunction(ExposedVoidFunc func, String functionName, Class<?>... types) {
        checkDeleted();
        ExposedVoidFunction exposedFunction = new ExposedVoidFunction(func, functionName, types);
        CppJsLibNative.exposeVoidFunction(id, exposedFunction.getFunc(), exposedFunction.getName(), exposedFunction.getArgTypes());
    }

    /**
     * Check the arguments given and convert them to a String array
     *
     * @param args  the args to check
     * @param types the argument types
     * @return the resulting String array
     */
    private String[] checkArgs(Object[] args, Class<?>... types) {
        assert args.length == types.length : "Number of arguments does not match: " + args.length + " vs. " + types.length;

        //noinspection ConstantConditions
        if (args.length != types.length) {
            throw new RuntimeException("Wrong length");
        }

        for (int i = 0; i < args.length; i++) {
            var cls1 = utils.toObjClass(args[i].getClass());
            var cls2 = utils.toObjClass(types[i]);

            assert cls1 == cls2 : "Arguments do not match: Expected " + cls2.getName() + ", got " + cls1.getName();

            //noinspection ConstantConditions
            if (cls1 != cls2) {
                throw new RuntimeException("Arguments do not match: Expected " + cls2.getName() + ", got " + cls1.getName());
            }
        }

        String[] strArgs = new String[args.length];

        for (int i = 0; i < args.length; i++) {
            strArgs[i] = utils.objToString(args[i], types[i]);
        }

        return strArgs;
    }

    /**
     * Import a void function from JavaScript.
     * This will throw an {@link OperationNotSupportedException} if the C++ library was built without websocket protocol support
     *
     * @param name  the name of the function in js
     * @param types the type classes of all arguments
     * @return a {@link JavaScriptVoidFunc} to call
     * @throws CppOutOfMemoryException if the C++ library returned that there was not enough memory available
     */
    public JavaScriptVoidFunc importVoidFunction(String name, Class<?>... types) throws CppOutOfMemoryException {
        checkDeleted();

        String[] argTypes = new String[types.length];
        for (int i = 0; i < argTypes.length; i++) {
            argTypes[i] = types[i].getName();
        }

        int fnID = CppJsLibNative.importFunction(id, name, "void", argTypes, -1);
        if (fnID == -1) {
            throw new CppOutOfMemoryException("The library returned that no memory could be allocated");
        }

        return args -> {
            String[] strArgs = checkArgs(args, types);
            CppJsLibNative.callVoidJsFunction(id, fnID, strArgs);
        };
    }

    /**
     * Import a non-void function from JavaScript.
     * This will throw an {@link OperationNotSupportedException} if the C++ library was built without websocket protocol support
     *
     * @param name       the name of the function in js
     * @param wait       a timeout to not wait for all clients to respond. Or -1 to wait indefinitely
     * @param returnType the return type class
     * @param types      the type classes
     * @param <R>        the return type
     * @return a {@link JavaScriptFunc} to call
     * @throws CppOutOfMemoryException if the C++ library returned that there was not enough memory available
     */
    public <R> JavaScriptFunc<R> importFunction(String name, int wait, Class<R> returnType, Class<?>... types) throws CppOutOfMemoryException {
        checkDeleted();

        if (!CppJsLib.hasWebsocketSupport()) {
            try {
                throw new OperationNotSupportedException("CppJsLib was built without websocket protocol support. This feature is required to import non-void JavaScript functions");
            } catch (OperationNotSupportedException e) {
                throw new RuntimeException(e);
            }
        }

        String[] argTypes = new String[types.length];
        for (int i = 0; i < argTypes.length; i++) {
            argTypes[i] = types[i].getName();
        }

        int fnID = CppJsLibNative.importFunction(id, name, returnType.getName(), argTypes, wait);
        if (fnID == -1) {
            throw new CppOutOfMemoryException("The library returned that no memory could be allocated");
        }

        return args -> {
            String[] strArgs = checkArgs(args, types);
            return utils.toObject(returnType, CppJsLibNative.callJSFunction(id, fnID, strArgs));
        };
    }

    /**
     * Check if {@link #close()} has already been called
     */
    private void checkDeleted() {
        if (deleted) {
            try {
                throw new ObjectAlreadyDeletedException("close() has already been called. Cannot accept any more calls");
            } catch (ObjectAlreadyDeletedException e) {
                throw new RuntimeException(e);
            }
        }
    }

    /**
     * Delete this instance of WebGUI. Please call this when finished using it to free up memory
     */
    private void delete() {
        checkDeleted();

        CppJsLibNative.deleteWebGUI(id);
        deleted = true;
    }

    /**
     * Close all resources. Please call this when finished using this object
     */
    public void close() {
        cleanable.clean();
    }
}
