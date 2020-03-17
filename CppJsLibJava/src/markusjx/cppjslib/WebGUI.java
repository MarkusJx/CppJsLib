package markusjx.cppjslib;

import markusjx.cppjslib.functional.ExposedFunction;
import markusjx.cppjslib.functional.ExposedVoidFunction;
import markusjx.cppjslib.interfaces.*;
import markusjx.cppjslib.nt.CppJsLibNative;

public class WebGUI {
    private int id;

    public WebGUI(String base_dir) {
        id = CppJsLibNative.initWebGUI(base_dir);
        System.out.println(id);
    }

    public WebGUI(String base_dir, String cert_path, String private_key_path) {
        id = CppJsLibNative.initWebGUI(base_dir, cert_path, private_key_path, 0);
    }

    public WebGUI(String base_dir, String cert_path, String private_key_path, int websocket_fallback_plain) {
        id = CppJsLibNative.initWebGUI(base_dir, cert_path, private_key_path, websocket_fallback_plain);
    }

    public boolean running() {
        return CppJsLibNative.running(id);
    }

    public boolean stopped() {
        return CppJsLibNative.stopped(id);
    }

    public void checkPorts(boolean val) {
        CppJsLibNative.checkPorts(id, val);
    }

    public boolean checkPorts() {
        return CppJsLibNative.checkPorts(id);
    }

    public void setLogger(LoggingFunction loggingFunction) {
        CppJsLibNative.setLogger(id, loggingFunction);
    }

    public void setError(LoggingFunction errorFunction) {
        CppJsLibNative.setError(id, errorFunction);
    }

    public void setWebSocketOpenHandler(Handler handler) {
        CppJsLibNative.setWebSocketOpenHandler(id, handler);
    }

    public void setWebSocketCloseHandler(Handler handler) {
        CppJsLibNative.setWebSocketCloseHandler(id, handler);
    }

    public boolean start(int port, int websocketPort, String host) {
        return CppJsLibNative.start(id, port, websocketPort, host, true);
    }

    public boolean start(int port, int websocketPort, String host, boolean block) {
        return CppJsLibNative.start(id, port, websocketPort, host, block);
    }

    public boolean stop() {
        return CppJsLibNative.stop(id, true, -1);
    }

    public boolean stop(boolean block) {
        return CppJsLibNative.stop(id, block, -1);
    }

    public boolean stop(boolean block, int maxWaitSeconds) {
        return CppJsLibNative.stop(id, block, maxWaitSeconds);
    }

    public <R> void exposeFunction(ExposedFunc func, String functionName, Class<R> returnType, Class<?>... types) {
        ExposedFunction<R> exposedFunction = new ExposedFunction<>(func, functionName, returnType, types);
        CppJsLibNative.exposeFunction(id, exposedFunction.getFunc(), exposedFunction.getName(), exposedFunction.getReturnType(), exposedFunction.getArgTypes());
    }

    public void exposeVoidFunction(ExposedVoidFunc func, String functionName, Class<?>... types) {
        ExposedVoidFunction exposedFunction = new ExposedVoidFunction(func, functionName, types);
        CppJsLibNative.exposeVoidFunction(id, exposedFunction.getFunc(), exposedFunction.getName(), exposedFunction.getArgTypes());
    }

    private String[] checkArgs(Object[] args, Class<?>...types) throws Exception {
        if (args.length != types.length) {
            throw new Exception("Wrong length");
        }

        String[] strArgs = new String[args.length];


        for (int i = 0; i < args.length; i++) {
            strArgs[i] = utils.objToString(args[i], types[i]);
        }

        return strArgs;
    }

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

    public <R> JavaScriptFunc<R> importFunction(String name, int wait, Class<R> returnType, Class<?>... types) {
        String[] argTypes = new String[types.length];
        for (int i = 0; i < argTypes.length; i++) {
            argTypes[i] = types[i].getName();
        }
        int fnID = CppJsLibNative.importFunction(id, name, returnType.getName(), argTypes, wait);

        return args -> {
            try {
                String[] strArgs = checkArgs(args, types);
                return (R) CppJsLibNative.callJSFunction(id, fnID, strArgs);
            } catch (Exception e) {
                e.printStackTrace();
                return null;
            }
        };
    }

    public void delete() {
        CppJsLibNative.deleteWebGUI(id);
    }

    @SuppressWarnings("deprecation")
    public void finalize() {
        delete();
    }
}
