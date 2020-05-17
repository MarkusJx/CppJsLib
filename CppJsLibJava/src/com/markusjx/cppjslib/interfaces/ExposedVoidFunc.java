/*
 * ExposedVoidFunc.java
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
public interface ExposedVoidFunc {
    /**
     * Call the function
     *
     * @param args the arguments
     */
    void call(Object... args);
}
