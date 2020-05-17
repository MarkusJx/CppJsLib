/*
 * JavaScriptFunc.java
 *
 * Licensed under the MIT License
 *
 * Copyright (c) 2020 MarkusJx
 *
 * The full license including third-party licenses is available at https://github.com/MarkusJx/CppJsLib/blob/master/LICENSE
 */
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
    R[] invoke(Object... args);
}
