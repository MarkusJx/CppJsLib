#ifndef CPPJSLIB_WEBGUI_HPP
#define CPPJSLIB_WEBGUI_HPP

#define CPPJSLIB_EXPORT

#if defined(CPPJSLIB_STATIC_DEFINE) || defined(__LINUX__) || defined(__APPLE__)
#  define CPPJSLIB_EXPORT
#  define CPPJSLIB_NO_EXPORT
#else
#  ifndef CPPJSLIB_EXPORT
#    ifdef CppJsLib_EXPORTS
/* We are building this library */
#      define CPPJSLIB_EXPORT __declspec(dllexport)
#    else
/* We are using this library */
#      define CPPJSLIB_EXPORT __declspec(dllimport)
#    endif
#  endif

#  ifndef CPPJSLIB_NO_EXPORT
#    define CPPJSLIB_NO_EXPORT
#  endif
#endif

#ifndef CPPJSLIB_DEPRECATED
#  define CPPJSLIB_DEPRECATED __declspec(deprecated)
#endif

#ifndef CPPJSLIB_DEPRECATED_EXPORT
#  define CPPJSLIB_DEPRECATED_EXPORT CPPJSLIB_EXPORT CPPJSLIB_DEPRECATED
#endif

#ifndef CPPJSLIB_DEPRECATED_NO_EXPORT
#  define CPPJSLIB_DEPRECATED_NO_EXPORT CPPJSLIB_NO_EXPORT CPPJSLIB_DEPRECATED
#endif

#if 0 /* DEFINE_NO_DEPRECATED */
#  ifndef CPPJSLIB_NO_DEPRECATED
#    define CPPJSLIB_NO_DEPRECATED
#  endif
#endif

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)
#   define CPPJSLIB_WINDOWS
#else
#   undef CPPJSLIB_WINDOWS
#endif

#include <map>
#include <vector>
#include <string>
#include <functional>
#include <sstream>
#include <iostream>

#define expose(func) _exportFunction(func, #func)
#define importFunction(func) _importJsFunction(func, #func)
#define getHttpServer() _getHttpServer<httplib::Server*>()

#define CPPJSLIB_DURATION_INFINITE -1

namespace CppJsLib {
    CPPJSLIB_EXPORT std::string *parseJSONInput(int *size, const std::string &args);

    CPPJSLIB_EXPORT std::string stringArrayToJSON(std::vector<std::string> *v);

    CPPJSLIB_EXPORT std::string stringToJSON(std::string s);

    CPPJSLIB_EXPORT void
    init_jsFn(const char *pattern, void *httplib_server, std::vector<void *> *responses, bool *resolved);

    CPPJSLIB_EXPORT void call_jsFn(std::vector<std::string> *argV, std::vector<void *> *responses, bool *resolved);

    CPPJSLIB_EXPORT std::string *createStringArrayFromJSON(int *size, const std::string &data);

    template<class>
    struct JsFunction;

    template<class>
    struct TypeConverter;

    template<class>
    struct ExposedFunction;

    template<typename T>
    struct function_traits;

    template<class T>
    inline std::string getEl(T dt) {
        return std::to_string(dt);
    }

    template<class ...Args>
    inline void ConvertToString(std::vector<std::string> *argV, Args...args) {
        auto x = {(argV->push_back(args), 0)...};
    }

    template<>
    struct JsFunction<void()> {
    public:
        void init(const std::string &name, void *httplib_server) {
            std::string r = "/listenfunc_";
            r.append(name);
            init_jsFn(r.c_str(), httplib_server, &responses, &resolved);
        }

        void operator()() {
            std::vector<std::string> argV;
            call_jsFn(&argV, &responses, &resolved);
        }

    private:
        bool resolved = false;
        std::vector<void *> responses;
    };

    template<class... Args>
    struct JsFunction<void(Args ...)> {
    public:
        void init(const std::string &name, void *httplib_server) {
            std::string r = "/listenfunc_";
            r.append(name);
            init_jsFn(r.c_str(), httplib_server, &responses, &resolved);
        }

        void operator()(Args ... args) {
            std::vector<std::string> argV;
            auto x = {(ConvertToString(&argV, getEl(args)), 0)...};
            call_jsFn(&argV, &responses, &resolved);
        }

    private:
        bool resolved = false;
        std::vector<void *> responses;
    };

    template<size_t SIZE, class T>
    inline size_t array_size(T (&arr)[SIZE]) {
        return SIZE;
    }

    template<class R>
    struct TypeConverter<R *> {
        static std::string toString(R toConvert) {
            size_t size = array_size(toConvert);
            std::vector<std::string> stringVector;
            for (int i = 0; i < size; i++) {
                stringVector.push_back(std::to_string(toConvert[i]));
            }

            std::string res = stringArrayToJSON(&stringVector);
            std::vector<std::string>().swap(stringVector);
            return res;
        }
    };

    template<class R>
    struct TypeConverter {
        static std::string toString(R toConvert) {
            return stringToJSON(std::to_string(toConvert));
        }
    };

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
            _f = std::move(f);
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
        ExposedFunction<void(Args...)> *exposedFn = new(std::nothrow) ExposedFunction<void(Args...)>(
                std::function < void(Args...) > (f), name);
        return exposedFn;
    }

    template<class R, class... Args>
    ExposedFunction<R(Args...)> *_exposeFunc(R(*f)(Args...), const std::string &name) {
        ExposedFunction<R(Args...)> *exposedFn = new(std::nothrow) ExposedFunction<R(Args...)>(
                std::function < R(Args...) > (f), name);
        return exposedFn;
    }

    struct Caller {
        template<class R, class...Args>
        static std::string call(ExposedFunction<R(Args...)> *eF, const std::string &args) {
            int size = 0;
            auto *argArr = parseJSONInput(&size, args);

            R result = eF->operator()(size, argArr);

            return TypeConverter<R>::toString(result);
        }

        template<class...Args>
        static std::string call(ExposedFunction<void(Args...)> *eF, const std::string &args) {
            int size = 0;
            auto *argArr = parseJSONInput(&size, args);

            eF->operator()(size, argArr);
            return "";
        }
    };

    class WebGUI {
    public:
        CPPJSLIB_EXPORT explicit WebGUI(const std::string &base_dir);

        template<class...Args>
        inline void _exportFunction(void(*f)(Args...), std::string name) {
            loggingF("[CppJsLib] Exposing void function with name " + name);
            if (running) {
                errorF("[CppJsLib] Cannot expose function " + name + " since the web server is already running");
                return;
            }
            auto exposedF = _exposeFunc(f, name);

            if (exposedF) {
                funcVector.push_back(static_cast<void *>(exposedF));

#ifdef CPPJSLIB_WINDOWS
                initMap.insert(std::pair<char *, char *>(_strdup(name.c_str()), _strdup(exposedF->toString().c_str())));
#else
                initMap.insert(std::pair<char *, char *>(strdup(name.c_str()), strdup(exposedF->toString().c_str())));
#endif
                std::string r = "/callfunc_";
                r.append(name);
                callFromPost(r.c_str(), [exposedF](std::string req_body) {
                    return Caller::call(exposedF, req_body);
                });
            } else {
                errorF("[CppJsLib] Cannot expose function " + name + ": Unable to allocate memory");
            }
        }

        template<class R, class...Args>
        inline void _exportFunction(R(*f)(Args...), std::string name) {
            loggingF("[CppJsLib] Exposing function with name " + name);
            if (running) {
                errorF("[CppJsLib] Cannot expose function " + name + " since the web server is already running");
                return;
            }
            auto exposedF = _exposeFunc(f, name);

            if (exposedF) {
                funcVector.push_back(static_cast<void *>(exposedF));

#ifdef CPPJSLIB_WINDOWS
                initMap.insert(std::pair<char *, char *>(_strdup(name.c_str()), _strdup(exposedF->toString().c_str())));
#else
                initMap.insert(std::pair<char *, char *>(strdup(name.c_str()), strdup(exposedF->toString().c_str())));
#endif
                std::string r = "/callfunc_";
                r.append(name);
                callFromPost(r.c_str(), [exposedF](std::string req_body) {
                    return Caller::call(exposedF, req_body);
                });
            } else {
                errorF("[CppJsLib] Cannot expose function " + name + ": Unable to allocate memory");
            }
        }

        template<class...Args>
        inline void _importJsFunction(std::function<void(Args...)> *function, std::string fName) {
            if (fName[0] == '&') {
                fName.erase(0, 1); // Delete first character as it is a &
            }

            loggingF("[CppJsLib] Importing js function with name " + fName);
            JsFunction<void(Args...)> *f = (JsFunction<void(Args...)> *) malloc(sizeof(JsFunction<void(Args...)>));
            if (f != nullptr) {
                f->init(fName, server);
                jsFuncVector.push_back(static_cast<void *>(f));
                *function = [f](Args...args) {
                    f->operator()(args...);
                };
            } else {
                errorF("[CppJsLib] Could not import function " + fName + ": Unable to allocate memory");
            }
        }

        CPPJSLIB_EXPORT bool start(int port, const std::string &host = "localhost", bool block = true);

        CPPJSLIB_EXPORT void setLogger(std::function<void(const std::string &)> function);

        CPPJSLIB_EXPORT void setError(std::function<void(const std::string &)> function);

        /**
         * A function used by the getHttpServer macro
         *
         * @warning Please DO NOT USE this function
         * @tparam T the param to convert the server pointer to, MUST be httplib::Server*
         * @return a pointer to the http Server of this instance
         */
        template<class T>
        inline T _getHttpServer() {
            return static_cast<T>(server);
        }

        CPPJSLIB_EXPORT ~WebGUI();

        bool running;
        bool stopped;
    private:
        void *server;
        std::map<char *, char *> initMap;
        std::vector<void *> funcVector;
        std::vector<void *> jsFuncVector;
        using PostHandler = std::function<std::string(std::string req_body)>;
        std::function<void(const std::string &)> loggingF;
        std::function<void(const std::string &)> errorF;

        CPPJSLIB_EXPORT void callFromPost(const char *target, const PostHandler &handler);
    };

    CPPJSLIB_EXPORT bool stop(WebGUI *webGui, bool block = true, int maxWaitSeconds = CPPJSLIB_DURATION_INFINITE);
}

#endif //CPPJSLIB_WEBGUI_HPP
