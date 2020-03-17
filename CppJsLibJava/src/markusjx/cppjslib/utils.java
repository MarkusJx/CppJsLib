package markusjx.cppjslib;

import markusjx.cppjslib.nt.CppJsLibNative;

public class utils {
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
}
