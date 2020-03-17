package markusjx.cppjslib.functional;

import markusjx.cppjslib.interfaces.CExposedVoidFunc;
import markusjx.cppjslib.interfaces.ExposedVoidFunc;
import markusjx.cppjslib.utils;

public class ExposedVoidFunction {
    private Class<?>[] types;
    private ExposedVoidFunc func;
    private String name;

    public ExposedVoidFunction(ExposedVoidFunc f, String name, Class<?>... types) {
        func = f;
        this.name = name;
        this.types = types;
    }

    public CExposedVoidFunc getFunc() {
        return types -> {
            try {
                Object[] args = new Object[types.length];
                for (int i = 0; i < types.length; i++) {
                    args[i] = utils.toObject(this.types[i], types[i]);
                }
                call(args);
            } catch (Exception e) {
                e.printStackTrace();
            }
        };
    }

    public void call(Object... args) throws Exception {
        if (args.length != types.length) {
            throw new Exception("Wrong length");
        }

        func.call(args);
    }

    public String[] getArgTypes() {
        String[] tmp = new String[types.length];
        for (int i = 0; i < tmp.length; i++) {
            tmp[i] = types[i].getName();
        }

        return tmp;
    }

    public String getName() {
        return name;
    }

    public String getReturnType() {
        return void.class.getName();
    }
}
