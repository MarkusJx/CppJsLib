/*
 * CppOutOfMemoryException.java
 *
 * Licensed under the MIT License
 *
 * Copyright (c) 2020 MarkusJx
 *
 * The full license including third-party licenses is available at https://github.com/MarkusJx/CppJsLib/blob/master/LICENSE
 */
package com.markusjx.cppjslib.exception;

/**
 * An exception thrown when the C++ library has not enough memory
 */
public class CppOutOfMemoryException extends CppJsLibException {
    /**
     * The CppOutOfMemoryException constructor
     *
     * @param message the exception message
     */
    public CppOutOfMemoryException(String message) {
        super(message);
    }
}
