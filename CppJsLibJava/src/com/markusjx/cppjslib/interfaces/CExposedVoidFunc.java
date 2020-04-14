package com.markusjx.cppjslib.interfaces;

/**
 * A Interface for a void function exposed to JavaScript
 */
public interface CExposedVoidFunc {
    /**
     * Call the function
     *
     * @param args the arguments
     */
    void call(String[] args);
}
