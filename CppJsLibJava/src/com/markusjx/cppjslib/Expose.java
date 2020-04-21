package com.markusjx.cppjslib;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation to expose a function to JavaScript
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Expose {
    /**
     * Set a custom name
     *
     * @return the custom name
     */
    public String name() default "";
}