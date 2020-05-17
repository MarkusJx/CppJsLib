/*
 * ExposedFunction.java
 *
 * Licensed under the MIT License
 *
 * Copyright (c) 2020 MarkusJx
 *
 * The full license including third-party licenses is available at https://github.com/MarkusJx/CppJsLib/blob/master/LICENSE
 */
package com.markusjx.cppjslib.functional;

import com.markusjx.cppjslib.interfaces.CExposedFunc;
import com.markusjx.cppjslib.interfaces.ExposedFunc;
import com.markusjx.cppjslib.util.utils;

/**
 * A class for an exposed function to JavaScript.
 * All functions in here will be called by {@link com.markusjx.cppjslib.WebGUI}.
 * Should not be called by anyone else
 *
 * @param <R> the return type
 */
public final class ExposedFunction<R> {
    private final Class<?>[] types;
    private final ExposedFunc func;
    private final String name;
    private final Class<R> returnType;

    /**
     * The ExposedFunction constructor
     *
     * @param f          a {@link ExposedFunc} to be called
     * @param name       the name of the function
     * @param returnType the return type class
     * @param types      the type classes
     */
    public ExposedFunction(ExposedFunc f, String name, Class<R> returnType, Class<?>... types) {
        func = f;
        this.name = name;
        this.returnType = returnType;
        this.types = types;
    }

    /**
     * Get the underlying {@link CExposedFunc}
     *
     * @return the {@link CExposedFunc}
     */
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

    /**
     * Call the function
     *
     * @param args the function args
     * @return the result of the function
     * @throws Exception if the arguments do not match
     */
    public Object call(Object... args) throws Exception {
        if (args.length != types.length) {
            throw new Exception("Wrong length");
        }

        return func.call(args);
    }

    /**
     * Get the arg types
     *
     * @return the arg types
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
     */
    public String getReturnType() {
        return returnType.getName();
    }
}
