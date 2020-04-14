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
