/*
 * ObjectAlreadyDeletedException.java
 *
 * Licensed under the MIT License
 *
 * Copyright (c) 2020 MarkusJx
 *
 * The full license including third-party licenses is available at https://github.com/MarkusJx/CppJsLib/blob/master/LICENSE
 */
package com.markusjx.cppjslib.exception;

/**
 * An exception thrown when the C++ object has already been deleted but it was tried to access it anyway
 */
public class ObjectAlreadyDeletedException extends CppJsLibException {
    /**
     * The CppJsLibException constructor
     *
     * @param message the exception message
     */
    public ObjectAlreadyDeletedException(String message) {
        super(message);
    }
}
