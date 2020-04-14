package com.markusjx.cppjslib;

import com.markusjx.cppjslib.functional.ExposedFunction;
import com.markusjx.cppjslib.functional.ExposedVoidFunction;
import com.markusjx.cppjslib.interfaces.*;
import com.markusjx.cppjslib.nt.CppJsLibNative;
import com.markusjx.cppjslib.util.utils;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;

/**
 * The main WebGUI class
 */
@SuppressWarnings("unused")
public class WebGUI {
    private final int id;
    private boolean CCheckPorts;
    private boolean checkPorts;
    private boolean deleted;

    /**
     * Create a WebGUI instance without a base directory.
     * May only be used to start without a http(s) server ({@link #startNoWeb(int)}, {@link #startNoWeb(int, boolean)})
     */
    public WebGUI() {
        id = CppJsLibNative.initWebGUI("");
        CCheckPorts = false;
        checkPorts = true;
        deleted = false;
        CppJsLibNative.checkPorts(id, false);
    }

    /**
     * Create a WebGUI instance
     *
     * @param base_dir the base directory
     */
    public WebGUI(String base_dir) {
        id = CppJsLibNative.initWebGUI(base_dir);
        CCheckPorts = false;
        checkPorts = true;
        deleted = false;
        CppJsLibNative.checkPorts(id, false);
    }

    /**
     * Create a WebGUI instance with SSL/TLS enabled
     *
     * @param base_dir         the base directory
     * @param cert_path        the certificate path
     * @param private_key_path the private key path
     */
    public WebGUI(String base_dir, String cert_path, String private_key_path) {
        id = CppJsLibNative.initWebGUI(base_dir, cert_path, private_key_path, 0);
        CCheckPorts = false;
        checkPorts = true;
        deleted = false;
        CppJsLibNative.checkPorts(id, false);
    }

    /**
     * Create a WebGUI instance with SSL/TLS enabled
     *
     * @param base_dir                 the base directory
     * @param cert_path                the certificate path
     * @param private_key_path         the private key path
     * @param websocket_fallback_plain a websocket fallback port, if encryption did fail
     */
    public WebGUI(String base_dir, String cert_path, String private_key_path, int websocket_fallback_plain) {
        id = CppJsLibNative.initWebGUI(base_dir, cert_path, private_key_path, websocket_fallback_plain);
        CCheckPorts = false;
        checkPorts = true;
        deleted = false;
        CppJsLibNative.checkPorts(id, false);
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
        return CppJsLibNative.running(id);
    }

    /**
     * Check if the servers are stopped
     *
     * @return true, if the servers are stopped
     */
    public boolean stopped() {
        return CppJsLibNative.stopped(id);
    }

    /**
     * Sets if the application should check if any ports are in use
     *
     * @param val check if the ports are in use
     */
    public void checkPorts(boolean val) {
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
        CppJsLibNative.setLogger(id, loggingFunction);
    }

    /**
     * Set an error logger
     *
     * @param errorFunction a {@link LoggingFunction} to log errors
     */
    public void setError(LoggingFunction errorFunction) {
        CppJsLibNative.setError(id, errorFunction);
    }

    /**
     * Set a handler which triggers if a client connects to a websocket port
     *
     * @param handler the handler to be called
     */
    public void setWebSocketOpenHandler(Handler handler) {
        CppJsLibNative.setWebSocketOpenHandler(id, handler);
    }

    /**
     * Set a handler which triggers if a client disconnects from a websocket port
     *
     * @param handler the handler to be called
     */
    public void setWebSocketCloseHandler(Handler handler) {
        CppJsLibNative.setWebSocketCloseHandler(id, handler);
    }

    /**
     * Start all servers. Blocking call.
     *
     * @param port          the port of the http server
     * @param websocketPort the port of the websocket server
     * @param host          the host address
     * @return if the operation was successful
     */
    public boolean start(int port, int websocketPort, String host) {
        if (!CCheckPorts && checkPorts && portsInUse(host, port, websocketPort)) {
            System.err.println("Some ports are already in use. Cannot start.");
            return false;
        } else {
            return CppJsLibNative.start(id, port, websocketPort, host, true);
        }
    }

    /**
     * Start all servers
     *
     * @param port          the port if the http server
     * @param websocketPort the port of the websocket server
     * @param host          the host address
     * @param block         if this is a blocking call
     * @return if the operation was successful. (Returns false or...blocks)
     */
    public boolean start(int port, int websocketPort, String host, boolean block) {
        if (!CCheckPorts && checkPorts && portsInUse(host, port, websocketPort)) {
            System.err.println("Some ports are already in use. Cannot start.");
            return false;
        } else {
            return CppJsLibNative.start(id, port, websocketPort, host, block);
        }
    }

    /**
     * Start only the websocket servers. Blocking call.
     *
     * @param port the port to listen on
     * @return if the operation was successful. (Can only return false. Really. Blocks otherwise.)
     */
    public boolean startNoWeb(int port) {
        if (!CCheckPorts && checkPorts && portsInUse("localhost", port)) {
            System.err.println("Some ports are already in use. Cannot start.");
            return false;
        } else {
            return CppJsLibNative.startNoWeb(id, port, true);
        }
    }

    /**
     * Start only the websocket servers
     *
     * @param port  the port to listen on
     * @param block if this is a blocking call
     * @return if the operation was successful
     */
    public boolean startNoWeb(int port, boolean block) {
        if (!CCheckPorts && checkPorts && portsInUse("localhost", port)) {
            System.err.println("Some ports are already in use. Cannot start.");
            return false;
        } else {
            return CppJsLibNative.startNoWeb(id, port, block);
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
        CppJsLibNative.setMountPoint(id, mnt, dir);
    }

    /**
     * Remove a mount point. Read more at the http server doc
     *
     * @param mnt the mount point to remove
     * @see <a href="https://github.com/yhirose/cpp-httplib#static-file-server">yhirose/cpp-httplib</a>
     */
    public void removeMountPoint(String mnt) {
        CppJsLibNative.removeMountPoint(id, mnt);
    }

    /**
     * Stop all servers. Blocking call
     *
     * @return if the operation was successful. Can only return true or block indefinitely
     */
    public boolean stop() {
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
        return CppJsLibNative.stop(id, block, -1);
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
        return CppJsLibNative.stop(id, block, maxWaitSeconds);
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
        ExposedVoidFunction exposedFunction = new ExposedVoidFunction(func, functionName, types);
        CppJsLibNative.exposeVoidFunction(id, exposedFunction.getFunc(), exposedFunction.getName(), exposedFunction.getArgTypes());
    }

    /**
     * Check the arguments given and convert them to a String array
     *
     * @param args  the args to check
     * @param types the argument types
     * @return the resulting String array
     * @throws Exception if any lengths do not match
     */
    private String[] checkArgs(Object[] args, Class<?>... types) throws Exception {
        if (args.length != types.length) {
            throw new Exception("Wrong length");
        }

        String[] strArgs = new String[args.length];


        for (int i = 0; i < args.length; i++) {
            strArgs[i] = utils.objToString(args[i], types[i]);
        }

        return strArgs;
    }

    /**
     * Import a void function from JavaScript
     *
     * @param name  the name of the function in js
     * @param types the type classes of all arguments
     * @return a {@link JavaScriptVoidFunc} to call
     */
    public JavaScriptVoidFunc importVoidFunction(String name, Class<?>... types) {
        String[] argTypes = new String[types.length];
        for (int i = 0; i < argTypes.length; i++) {
            argTypes[i] = types[i].getName();
        }
        int fnID = CppJsLibNative.importFunction(id, name, "void", argTypes, -1);

        return args -> {
            try {
                String[] strArgs = checkArgs(args, types);
                CppJsLibNative.callVoidJsFunction(id, fnID, strArgs);
            } catch (Exception e) {
                e.printStackTrace();
            }
        };
    }

    /**
     * Import a non-void function from JavaScript
     *
     * @param name       the name of the function in js
     * @param wait       a timeout to not wait for all clients to respond. Or -1 to wait indefinitely
     * @param returnType the return type class
     * @param types      the type classes
     * @param <R>        the return type
     * @return a {@link JavaScriptFunc} to call
     */
    public <R> JavaScriptFunc<R> importFunction(String name, int wait, Class<R> returnType, Class<?>... types) {
        String[] argTypes = new String[types.length];
        for (int i = 0; i < argTypes.length; i++) {
            argTypes[i] = types[i].getName();
        }
        int fnID = CppJsLibNative.importFunction(id, name, returnType.getName(), argTypes, wait);

        return args -> {
            try {
                String[] strArgs = checkArgs(args, types);
                return utils.toObject(returnType, CppJsLibNative.callJSFunction(id, fnID, strArgs));
            } catch (Exception e) {
                e.printStackTrace();
                return null;
            }
        };
    }

    /**
     * Delete this instance of WebGUI. Please call this when finished using it to free up memory
     */
    public void delete() {
        if (!deleted) {
            CppJsLibNative.deleteWebGUI(id);
            deleted = true;
        }
    }

    /**
     * Delete this instance of WebGUI. Does not work all the time and is therefore deprecated. Use {@link #delete()}. Please.
     */
    @SuppressWarnings("deprecation")
    public void finalize() {
        delete();
    }
}
