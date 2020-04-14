package com.markusjx.cppjslib.interfaces;

/**
 * A Interface for a function exposed to JavaScript
 */
public interface CExposedFunc {
    /**
     * Call the function
     *
     * @param args the arguments
     * @return the return value
     */
    String call(String[] args);
}
