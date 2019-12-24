//
// Created by Markus on 11/12/2019.
//

#ifndef CPPJSLIB_FUNCTYPES_HPP
#define CPPJSLIB_FUNCTYPES_HPP

#include <functional>
#include <iostream>
#include <sstream>

/**
 * Source 1: https://stackoverflow.com/a/9065203
 * Source 2: https://stackoverflow.com/a/9077725
 */
namespace CppJsLib {
    template<class>
    struct ExposedFunction;

    template<typename T>
    struct function_traits;

    template<typename R, typename ...Args>
    struct function_traits<std::function<R(Args...)>> {
        static const size_t nargs = sizeof...(Args);

        template<size_t i>
        struct arg {
            typedef typename std::tuple_element<i, std::tuple<Args...>>::type type;
        };
    };

    template<typename type>
    std::string getTypeName() {
        if (std::is_same<int, type>::value) {
            return "int";
        } else if (std::is_same<int *, type>::value) {
            return "int[]";
        } else if (std::is_same<char, type>::value) {
            return "char";
        } else if (std::is_same<char *, type>::value) {
            return "char[]";
        } else if (std::is_same<std::string, type>::value) {
            return "string";
        } else if (std::is_same<std::string *, type>::value) {
            return "string[]";
        } else if (std::is_same<bool, type>::value) {
            return "bool";
        } else if (std::is_same<bool *, type>::value) {
            return "bool[]";
        } else if (std::is_same<float, type>::value) {
            return "float";
        } else if (std::is_same<float *, type>::value) {
            return "float[]";
        } else if (std::is_same<double, type>::value) {
            return "double";
        } else if (std::is_same<double *, type>::value) {
            return "double[]";
        } else {
            return "void";
        }
    }

    template<typename fun, size_t i>
    struct expose_helper {
        static void __expose(std::string *types) {
            expose_helper<fun, i - 1>::__expose(types);
            typedef typename function_traits<fun>::template arg<i - 1>::type type;

            types[i - 1] = getTypeName<type>();
        }
    };

    template<typename fun>
    struct expose_helper<fun, 0> {
        static void __expose(std::string *types) {}
    };

    template<typename T>
    struct remove_pointer {
        typedef T type;
    };

    template<typename T>
    struct remove_pointer<T *> {
        typedef typename remove_pointer<T>::type type;
    };

    template<class T>
    struct cString {
        static T convert(const std::string &data) {
            T ret;
            if (std::is_same<T, bool>::value) {
                if (data == "false") {
                    return false;
                } else if (data == "true") {
                    return true;
                } else {
                    std::cerr << "Convert error: cannot convert string '" << data << "' to bool" << std::endl;
                    return T();
                }
            }

            std::istringstream iss(data);
            if (data.find("0x") != std::string::npos) {
                iss >> std::hex >> ret;
            } else {
                iss >> std::dec >> ret;
            }

            if (iss.fail()) {
                std::cerr << "Convert error: cannot convert string '" << data << "' to value" << std::endl;
                return T();
            }
            return ret;
        }
    };

    std::string *createStringArrayFromJSON(int *size, const std::string &data);

    template<class T>
    struct cString<T *> {
        static T *convert(const std::string &data) {
            typedef typename remove_pointer<T>::type type;
            int size = 0;
            std::string *arr = createStringArrayFromJSON(&size, data);
            type *ret = new type[size];
            for (int i = 0; i < size; i++) {
                ret[i] = cString<type>::convert(arr[i]);
            }

            return ret;
        }
    };

    /**
     * Convert a String to a param T
     * Source: https://gist.github.com/timofurrer/2725779
     *
     * @tparam T the param to convert to
     * @param data the string to convert
     * @return the data
     */
    template<typename T>
    T ConvertString(const std::string &data) {
        if (!data.empty()) {
            return cString<T>::convert(data);
        }
        return T();
    }

    template<typename T>
    T *ConvertString(std::string *data) {
        return cString<T>::convert(data);
    }

    template<class... Args>
    struct ExposedFunction<void(Args...)> {
    public:
        ExposedFunction(std::function<void(Args...)>(f), const std::string &name) {
            _f = f;
            _name = name;

            typedef function_traits<std::function<void(Args...)>> fn_traits;
            nArgs = fn_traits::nargs;
            argTypes = new std::string[fn_traits::nargs];
            expose_helper<std::function<void(Args...)>, fn_traits::nargs>::__expose(argTypes);
            returnType = "void";
        }

        void operator()(int argc, std::string *args) {
            // This should be a precondition
            if (argc != sizeof...(Args)) {
                std::cerr << "Argument sizes do not match!" << std::endl;
                return;
            }

            auto sequence = std::index_sequence_for<Args...>{};
            return handleImpl(sequence, args);
        }

        template<std::size_t... S>
        void handleImpl(std::index_sequence<S...>, std::string *args) {
            _f(ConvertString<Args>(args[S])...);
        }

        std::string toString() {
            std::string tmp = returnType;
            tmp.append(" ").append(_name).append("(");

            for (int i = 0; i < nArgs; i++) {
                if (i > 0) tmp.append(", ");
                tmp.append(argTypes[i]);
            }
            tmp.append(")");

            return tmp;
        }

        std::string _name;
    private:
        std::function<void(Args...)> _f;

        int nArgs;
        std::string *argTypes;
        std::string returnType;
    };

    template<class R, class... Args>
    struct ExposedFunction<R(Args...)> {
    public:
        ExposedFunction(std::function<R(Args...)>(f), const std::string &name) {
            _f = f;
            _name = name;

            typedef function_traits<std::function<R(Args...)>> fn_traits;
            nArgs = fn_traits::nargs;
            argTypes = new std::string[fn_traits::nargs];
            expose_helper<std::function<R(Args...)>, fn_traits::nargs>::__expose(argTypes);
            returnType = getTypeName<R>();
        }

        R operator()(int argc, std::string *args) {
            // This should be a precondition
            if (argc != sizeof...(Args)) {
                return 0;
            }

            auto sequence = std::index_sequence_for<Args...>{};
            return handleImpl(sequence, args);
        }

        template<std::size_t... S>
        R handleImpl(std::index_sequence<S...>, std::string *args) {
            return _f(ConvertString<Args>(args[S])...);
        }

        std::string toString() {
            std::string tmp = returnType;
            tmp.append(" ").append(_name).append("(");

            for (int i = 0; i < nArgs; i++) {
                if (i > 0) tmp.append(", ");
                tmp.append(argTypes[i]);
            }
            tmp.append(")");

            return tmp;
        }

        std::string _name;
    private:
        std::function<R(Args...)> _f;

        int nArgs;
        std::string *argTypes;
        std::string returnType;
    };

    template<class... Args>
    ExposedFunction<void(Args...)> *_exposeFunc(void (*f)(Args...), const std::string &name) {
        return new ExposedFunction<void(Args...)>(std::function<void(Args...)>(f), name);
    }

    template<class R, class... Args>
    ExposedFunction<R(Args...)> *_exposeFunc(R(*f)(Args...), const std::string &name) {
        return new ExposedFunction<R(Args...)>(std::function<R(Args...)>(f), name);
    }
}

#endif //CPPJSLIB_FUNCTYPES_HPP