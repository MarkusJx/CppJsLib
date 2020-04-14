package com.markusjx.cppjslib.interfaces;

/**
 * A Interface for a function exposed to JavaScript
 */
public interface ExposedFunc {
    /**
     * Call the function
     *
     * @param args the arguments
     * @return the return value
     */
    Object call(Object... args);
}
