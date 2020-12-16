/*
 * LoggingFunction.java
 *
 * Licensed under the MIT License
 *
 * Copyright (c) 2020 MarkusJx
 *
 * The full license including third-party licenses is available at https://github.com/MarkusJx/CppJsLib/blob/master/LICENSE
 */
package com.markusjx.cppjslib.interfaces;

/**
 * A logging function interface.
 * Will be called by the C++ library
 */
@SuppressWarnings("unused")
public interface LoggingFunction {
    /**
     * Log a message
     *
     * @param message the message to be logged
     */
    void log(String message);
}
