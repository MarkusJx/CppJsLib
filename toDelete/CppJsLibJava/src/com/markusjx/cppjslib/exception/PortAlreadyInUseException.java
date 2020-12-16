/*
 * PortAlreadyInUseException.java
 *
 * Licensed under the MIT License
 *
 * Copyright (c) 2020 MarkusJx
 *
 * The full license including third-party licenses is available at https://github.com/MarkusJx/CppJsLib/blob/master/LICENSE
 */
package com.markusjx.cppjslib.exception;

/**
 * An exception thrown when a requested port is already in use
 */
public class PortAlreadyInUseException extends CppJsLibException {
    /**
     * The PortAlreadyInUseException constructor
     *
     * @param message the exception message
     */
    public PortAlreadyInUseException(String message) {
        super(message);
    }
}
