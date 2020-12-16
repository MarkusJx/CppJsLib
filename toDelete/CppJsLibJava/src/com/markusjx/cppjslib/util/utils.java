/*
 * utils.java
 *
 * Licensed under the MIT License
 *
 * Copyright (c) 2020 MarkusJx
 *
 * The full license including third-party licenses is available at https://github.com/MarkusJx/CppJsLib/blob/master/LICENSE
 */
package com.markusjx.cppjslib.util;

import com.markusjx.cppjslib.nt.CppJsLibNative;

/**
 * A generic util class used by some other classes.
 * Should not be used by anyone else
 */
public final class utils {
    /**
     * Convert a class array to a class
     *
     * @param array the array to get the class from
     * @return the resulting class
     */
    private static Class<?> toClass(Class<?> array) {
        if (Boolean[].class == array || boolean[].class == array) return Boolean.class;
        if (Byte[].class == array || byte[].class == array) return Byte.class;
        if (Short[].class == array || short[].class == array) return Short.class;
        if (Integer[].class == array || int[].class == array) return Integer.class;
        if (Long[].class == array || long[].class == array) return Long.class;
        if (Float[].class == array || float[].class == array) return Float.class;
        if (Double[].class == array || double[].class == array) return Double.class;
        return array;
    }

    /**
     * Convert a String array to an Object array
     *
     * @param cls       the class of the object
     * @param toConvert the array to convert
     * @param <R>       the return type
     * @return the resulting array
     */
    public static <R> R[] toObject(Class<R> cls, String[] toConvert) {
        Object[] tmp = new Object[toConvert.length];
        for (int i = 0; i < toConvert.length; i++) {
            tmp[i] = toObject(cls, toConvert[i]);
        }

        return (R[]) tmp;
    }

    /**
     * Convert a String to an object
     *
     * @param clazz the object class to convert to
     * @param value the value to convert
     * @return the resulting object
     */
    public static Object toObject(Class<?> clazz, String value) {
        if (clazz.isArray()) {
            String[] arr = CppJsLibNative.createStringArrayFromJSON(value);
            Object[] tmp = new Object[arr.length];
            for (int i = 0; i < arr.length; i++) {
                tmp[i] = toObject(toClass(clazz), arr[i]);
            }
            return tmp;
        }
        if (Boolean.class == clazz || boolean.class == clazz) return Boolean.parseBoolean(value);
        if (Byte.class == clazz || byte.class == clazz) return Byte.parseByte(value);
        if (Short.class == clazz || short.class == clazz) return Short.parseShort(value);
        if (Integer.class == clazz || int.class == clazz) return Integer.parseInt(value);
        if (Long.class == clazz || long.class == clazz) return Long.parseLong(value);
        if (Float.class == clazz || float.class == clazz) return Float.parseFloat(value);
        if (Double.class == clazz || double.class == clazz) return Double.parseDouble(value);
        return value;
    }

    /**
     * Convert an Object to a String
     *
     * @param obj  the Object to convert
     * @param type the type class of the object
     * @return the resulting string
     */
    public static String objToString(Object obj, Class<?> type) {
        if (type.isArray()) {
            Object[] arr = (Object[]) obj;
            String[] str = new String[arr.length];
            for (int i = 0; i < arr.length; i++) {
                str[i] = String.valueOf(arr[i]);
            }
            return CppJsLibNative.stringArrayToJSON(str);
        } else {
            return String.valueOf(obj);
        }
    }

    /**
     * Convert any class type to its class equivalent
     *
     * @param type the type to convert
     * @return the resulting type
     */
    public static Class<?> toObjClass(Class<?> type) {
        if (Boolean.class == type || boolean.class == type) return Boolean.class;
        if (Byte.class == type || byte.class == type) return Byte.class;
        if (Short.class == type || short.class == type) return Short.class;
        if (Integer.class == type || int.class == type) return Integer.class;
        if (Long.class == type || long.class == type) return Long.class;
        if (Float.class == type || float.class == type) return Float.class;
        if (Double.class == type || double.class == type) return Double.class;
        return type;
    }
}
