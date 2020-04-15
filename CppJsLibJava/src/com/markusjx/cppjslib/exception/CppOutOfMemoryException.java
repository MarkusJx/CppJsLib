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
