/*
 * CppJsLibException.java
 *
 * Licensed under the MIT License
 *
 * Copyright (c) 2020 MarkusJx
 *
 * The full license including third-party licenses is available at https://github.com/MarkusJx/CppJsLib/blob/master/LICENSE
 */
package com.markusjx.cppjslib.exception;

/**
 * A parent exception class to {@link CppOutOfMemoryException} and {@link OperationNotSupportedException}
 */
public class CppJsLibException extends Exception {
    /**
     * The CppJsLibException constructor
     *
     * @param message the exception message
     */
    public CppJsLibException(String message) {
        super(message);
    }
}
