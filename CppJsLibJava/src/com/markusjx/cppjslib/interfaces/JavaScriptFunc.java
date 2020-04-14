package com.markusjx.cppjslib.interfaces;

/**
 * A interface for an imported JavaScript function
 *
 * @param <R> the function return type
 */
public interface JavaScriptFunc<R> {
    /**
     * Call the function
     *
     * @param args the arguments
     * @return an array of all client returns
     */
    R[] call(Object... args);
}
