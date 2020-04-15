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
