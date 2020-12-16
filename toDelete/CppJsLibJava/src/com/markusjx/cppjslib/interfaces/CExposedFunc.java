/*
 * CExposedFunc.java
 *
 * Licensed under the MIT License
 *
 * Copyright (c) 2020 MarkusJx
 *
 * The full license including third-party licenses is available at https://github.com/MarkusJx/CppJsLib/blob/master/LICENSE
 */
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
