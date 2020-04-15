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
