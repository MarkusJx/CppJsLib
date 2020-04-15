package com.markusjx.cppjslib.exception;

/**
 * An exception thrown, when a operation is requested, but the C++ library was built without support for it
 */
public class OperationNotSupportedException extends CppJsLibException {
    /**
     * The OperationNotSupportedException constructor
     * @param message the exception message
     */
    public OperationNotSupportedException(String message) {
        super(message);
    }
}
