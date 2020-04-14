import com.markusjx.cppjslib.WebGUI;
import com.markusjx.cppjslib.interfaces.JavaScriptFunc;
import com.markusjx.cppjslib.interfaces.JavaScriptVoidFunc;

public class Main {
    private static void fn1(int i) {
        // Code
    }

    public static void main(String[] args) {
        // Create instance of WebGUI
        WebGUI gui = new WebGUI("web");

        // Expose void function, cast types to the required type,
        // set the function name and the argument types
        gui.exposeVoidFunction(types -> fn1((int) types[0]), "fn1", int.class);

        // Expose non-void function, cast types, set the function name,
        // the return type and the argument types
        //gui.exposeFunction(types -> fn2((String) types[0]), "fn2", int.class, String.class);

        // Import javascript void function with name and argument types
        JavaScriptVoidFunc fn = gui.importVoidFunction("func", int.class);

        // Import non-void function with name, a timeout, -1 equals infinite,
        // the return type and the argument types
        JavaScriptFunc<Integer> f = gui.importFunction("f", -1, int.class, int.class);

        // Start the servers with their ports on this machine, without blocking
        gui.start(8025, 8026, "localhost", false);

        // Stop the servers
        gui.stop(true);
    }
}
