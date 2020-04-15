import com.markusjx.cppjslib.Expose;
import com.markusjx.cppjslib.WebGUI;
import com.markusjx.cppjslib.exception.CppJsLibException;

public class Main {
    // Add @Expose to expose function
    @Expose
    public static void fn1(int i) {
        // Code
    }

    public static void fn2(String s) {
        // Code
    }

    public static void main(String[] args) throws CppJsLibException {
        // Create instance of WebGUI
        WebGUI gui = new WebGUI("web");

        // Expose all functions in this class
        gui.exposeAll(Main.class);

        // Manually expose a function, cast all types, enter argument types
        gui.exposeVoidFunction(args1 -> fn2((String) args1[0]), "fn2", String.class);

        // Import javascript void function with name and argument types
        var fn = gui.importVoidFunction("func", int.class);

        // Import non-void function with name, a timeout, -1 equals infinite,
        // the return type and the argument types
        var f = gui.importFunction("f", -1, int.class, int.class);

        // Start the servers with their ports on this machine, without blocking
        gui.start(8025, 8026, "localhost", false);

        // Stop the servers
        gui.stop();

        // Close all resources
        gui.close();
    }
}
