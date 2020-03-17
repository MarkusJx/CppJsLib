package markusjx.cppjslib.functional;

import markusjx.cppjslib.interfaces.CExposedFunc;
import markusjx.cppjslib.interfaces.ExposedFunc;
import markusjx.cppjslib.utils;

public class ExposedFunction<R> {
    private Class<?>[] types;
    private ExposedFunc func;
    private String name;
    private Class<R> returnType;

    public ExposedFunction(ExposedFunc f, String name, Class<R> returnType, Class<?>... types) {
        func = f;
        this.name = name;
        this.returnType = returnType;
        this.types = types;
    }

    public CExposedFunc getFunc() {
        return types -> {
            try {
                Object[] args = new Object[types.length];
                for (int i = 0; i < types.length; i++) {
                    args[i] = utils.toObject(this.types[i], types[i]);
                }
                return utils.objToString(call(args), returnType);
            } catch (Exception e) {
                e.printStackTrace();
                return null;
            }
        };
    }

    public Object call(Object... args) throws Exception {
        if (args.length != types.length) {
            throw new Exception("Wrong length");
        }

        return func.call(args);
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
        return returnType.getName();
    }
}
