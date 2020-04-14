package com.markusjx.cppjslib.functional;

import com.markusjx.cppjslib.interfaces.CExposedVoidFunc;
import com.markusjx.cppjslib.interfaces.ExposedVoidFunc;
import com.markusjx.cppjslib.util.utils;

/**
 * A class for a void function to be called from JavaScript
 * All functions in here will be called by {@link com.markusjx.cppjslib.WebGUI}.
 * Should not be called by anyone else
 */
public final class ExposedVoidFunction {
    private final Class<?>[] types;
    private final ExposedVoidFunc func;
    private final String name;

    /**
     * The ExposedVoidFunction constructor
     *
     * @param f     the {@link ExposedVoidFunc} to be called
     * @param name  the function name
     * @param types the argument type classes
     */
    public ExposedVoidFunction(ExposedVoidFunc f, String name, Class<?>... types) {
        func = f;
        this.name = name;
        this.types = types;
    }

    /**
     * Get the underlying {@link CExposedVoidFunc}
     *
     * @return the {@link CExposedVoidFunc}
     */
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

    /**
     * Call the function
     *
     * @param args the args
     * @throws Exception if the args do not match
     */
    public void call(Object... args) throws Exception {
        if (args.length != types.length) {
            throw new Exception("Wrong length");
        }

        func.call(args);
    }

    /**
     * Get the arg types
     *
     * @return the arg types as String array
     */
    public String[] getArgTypes() {
        String[] tmp = new String[types.length];
        for (int i = 0; i < tmp.length; i++) {
            tmp[i] = types[i].getName();
        }

        return tmp;
    }

    /**
     * Get the function name
     *
     * @return the function name
     */
    public String getName() {
        return name;
    }

    /**
     * Get the return type
     *
     * @return the return type as String
     * @deprecated This is not used. Just here if it is needed at some point in time or to be removed
     */
    @Deprecated(forRemoval = true)
    public String getReturnType() {
        return void.class.getName();
    }
}
