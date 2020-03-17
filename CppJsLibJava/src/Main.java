import markusjx.cppjslib.CppJsLib;
import markusjx.cppjslib.WebGUI;
import markusjx.cppjslib.interfaces.JavaScriptVoidFunc;

public class Main {
    public static WebGUI w;
    static JavaScriptVoidFunc fn;
    private static void f(int a) {
        System.out.println(a);
        fn.call(a);
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        fn.call(a);
    }

    public static void main(String[] args) throws InterruptedException {
        CppJsLib.setLogger(System.out::println);
        w = new WebGUI("web");
        w.checkPorts(false);
        w.exposeVoidFunction(types -> f((int) types[0]), "f", int.class);
        fn = w.importVoidFunction("func", int.class);
        w.start(8025, 8026, "localhost");
    }
}
