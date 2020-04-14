package com.markusjx.cppjslib.interfaces;

/**
 * A Interface for a function exposed to JavaScript
 */
public interface ExposedVoidFunc {
    /**
     * Call the function
     *
     * @param args the arguments
     */
    void call(Object... args);
}
