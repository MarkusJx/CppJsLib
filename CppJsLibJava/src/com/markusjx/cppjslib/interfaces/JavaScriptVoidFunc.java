/*
 * JavaScriptVoidFunc.java
 *
 * Licensed under the MIT License
 *
 * Copyright (c) 2020 MarkusJx
 *
 * The full license including third-party licenses is available at https://github.com/MarkusJx/CppJsLib/blob/master/LICENSE
 */
package com.markusjx.cppjslib.interfaces;

/**
 * A interface for an imported JavaScript void function
 */
public interface JavaScriptVoidFunc {
    /**
     * Call the function
     *
     * @param args the arguments
     */
    void invoke(Object... args);
}
