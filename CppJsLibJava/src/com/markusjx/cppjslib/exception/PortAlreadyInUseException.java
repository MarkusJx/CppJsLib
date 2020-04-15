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
