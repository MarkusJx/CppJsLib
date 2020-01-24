#ifndef CPPJSLIB_WEBGUI_HPP
#define CPPJSLIB_WEBGUI_HPP

#ifdef CPPJSLIB_GHBUILD
#  define CPPJSLIB_EXPORT
#endif

#ifdef CPPJSLIB_ENABLE_HTTPS
#   define CPPHTTPLIB_OPENSSL_SUPPORT
#else
#   undef CPPHTTPLIB_OPENSSL_SUPPORT
#   undef CPPJSLIB_ENABLE_HTTPS //Redundant, just adding this so CLion recognizes this macro as existing
#endif

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)
#   define CPPJSLIB_WINDOWS
#   undef CPPJSLIB_UNIX
#elif defined(__LINUX__) || defined(__APPLE__) || defined (__CYGWIN__)
#   define CPPJSLIB_UNIX
#   undef CPPJSLIB_WINDOWS
#endif

#if defined(CPPJSLIB_STATIC_DEFINE) || defined (CPPJSLIB_UNIX)
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

#include <map>
#include <utility>
#include <vector>
#include <string>
#include <functional>
#include <sstream>
#include <iostream>
#include <cstring>
#include <thread>

#ifdef CPPJSLIB_WINDOWS
#   define strdup _strdup
#endif

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
#   define CPPJSLIB_WS_PORT int websocketPort,
#else
#   define CPPJSLIB_WS_PORT
#endif

#define expose(func) _exportFunction(func, #func)
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
#   define importFunction(func, ...) _importJsFunction(func, #func, ##__VA_ARGS__)
#   define getWebServer() _getWebServer<websocketpp::server<websocketpp::config::asio>>()
#   ifdef CPPJSLIB_ENABLE_HTTPS
#       define getTLSWebServer() _getTLSWebServer<websocketpp::server<websocketpp::config::asio_tls>>()
#   endif
#endif
#ifdef CPPJSLIB_ENABLE_HTTPS
#   define getHttpsServer() _getHttpServer<httplib::SSLServer>()
#endif
#define getHttpServer() _getHttpServer<httplib::Server>()

#define CPPJSLIB_DURATION_INFINITE -1

namespace CppJsLib {
    CPPJSLIB_EXPORT std::string *parseJSONInput(int *size, const std::string &args);

    CPPJSLIB_EXPORT std::string stringArrayToJSON(std::vector<std::string> *v);

    CPPJSLIB_EXPORT std::string stringToJSON(std::string s);

    CPPJSLIB_EXPORT std::string *createStringArrayFromJSON(int *size, const std::string &data);

    template<class>
    struct TypeConverter;

    template<class>
    struct ExposedFunction;

    template<typename T>
    struct function_traits;

    template<class R>
    std::string getTypeName();

    template<typename T>
    T ConvertString(const std::string &data);

#ifdef CPPJSLIB_ENABLE_WEBSOCKET

    template<class>
    struct JsFunction;

    class WebGUI;

    CPPJSLIB_EXPORT void
    callJsFunc(const std::shared_ptr<WebGUI> &wGui, std::vector<std::string> *argV, const char *funcName,
               std::vector<char *> *results = nullptr, int wait = -1);

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
        JsFunction<void()>(std::string name, std::shared_ptr<WebGUI> _wGui) :
                returnType("void"), fnName(std::move(name)), wGui(std::move(_wGui)) {}

        void operator()() {
            std::vector<std::string> argV;
            callJsFunc(wGui, &argV, fnName.c_str());
        }

        ~JsFunction() = default;

    private:
        const std::string fnName;
        const std::string returnType;
        const std::shared_ptr<WebGUI> wGui;
    };

    template<class... Args>
    struct JsFunction<void(Args ...)> {
    public:
        JsFunction<void(Args...)>(std::string name, std::shared_ptr<WebGUI> _wGui) :
                returnType("void"), fnName(std::move(name)), wGui(std::move(_wGui)) {}

        void operator()(Args ... args) {
            std::vector<std::string> argV;
            auto x = {(ConvertToString(&argV, getEl(args)), 0)...};
            callJsFunc(wGui, &argV, fnName.c_str());
        }

        ~JsFunction() = default;

    private:
        const std::string fnName;
        const std::string returnType;
        const std::shared_ptr<WebGUI> wGui;
    };

    template<class R>
    struct JsFunction<std::vector<R>()> {
    public:
        JsFunction<std::vector<R>()>(std::string name, std::shared_ptr<WebGUI> _wGui, int waitS)
                : responseReturns(), returnType(getTypeName<R>()), fnName(std::move(name)), wGui(std::move(_wGui)) {
            wait = waitS;
        }

        std::vector<R> operator()() {
            std::vector<std::string> argV;
            callJsFunc(wGui, &argV, fnName.c_str(), &responseReturns, wait);

            std::vector<R> tmp;
            for (char *c : responseReturns) {
                tmp.push_back(ConvertString<R>(c));
                free(c);
            }
            std::vector<char *>().swap(responseReturns);

            return tmp;
        }

        ~JsFunction() {
            for (char *c : responseReturns) {
                free(c);
            }

            std::vector<char *>().swap(responseReturns);
        }

    private:
        const std::string fnName;
        const std::string returnType;
        const std::shared_ptr<WebGUI> wGui;
        int wait;
        std::vector<char *> responseReturns;
    };

    template<class R, class... Args>
    struct JsFunction<std::vector<R>(Args ...)> {
    public:
        JsFunction<std::vector<R>(Args...)>(std::string name, std::shared_ptr<WebGUI> _wGui, int waitS)
                : responseReturns(), returnType(getTypeName<R>()), fnName(std::move(name)), wGui(std::move(_wGui)) {
            wait = waitS;
        }

        std::vector<R> operator()(Args ... args) {
            std::vector<std::string> argV;
            auto x = {(ConvertToString(&argV, getEl(args)), 0)...};
            callJsFunc(wGui, &argV, fnName.c_str(), &responseReturns, wait);

            std::vector<R> tmp;
            for (char *c : responseReturns) {
                tmp.push_back(ConvertString<R>(c));
                free(c);
            }
            std::vector<char *>().swap(responseReturns);

            return tmp;
        }

        ~JsFunction() {
            for (char *c : responseReturns) {
                free(c);
            }

            std::vector<char *>().swap(responseReturns);
        }

    private:
        const std::string fnName;
        const std::string returnType;
        int wait;
        std::vector<char *> responseReturns;
        const std::shared_ptr<WebGUI> wGui;
    };

#endif

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
        auto *exposedFn = new(std::nothrow) ExposedFunction<void(Args...)>(
                std::function < void(Args...) > (f), name);
        return exposedFn;
    }

    template<class R, class... Args>
    ExposedFunction<R(Args...)> *_exposeFunc(R(*f)(Args...), const std::string &name) {
        auto *exposedFn = new(std::nothrow) ExposedFunction<R(Args...)>(
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

    CPPJSLIB_EXPORT void setLogger(std::function<void(const std::string &)> function);

    CPPJSLIB_EXPORT void setError(std::function<void(const std::string &)> function);


    class WebGUI {
    public:
#ifdef CPPJSLIB_ENABLE_HTTPS
        /**
         * @warning this constructor will be undeclared when built without ssl support
         */
        CPPJSLIB_EXPORT WebGUI(const std::string &base_dir, const std::string &cert_path,
                               const std::string &private_key_path, unsigned short websocket_plain_fallback_port = 0);

#endif

        CPPJSLIB_EXPORT explicit WebGUI(const std::string &base_dir);

        template<class...Args>
        inline void _exportFunction(void(*f)(Args...), std::string name) {
            _loggingF("[CppJsLib] Exposing void function with name " + name);
            if (running) {
                _errorF("[CppJsLib] Cannot expose function " + name + " since the web server is already running");
                return;
            }
            auto exposedF = _exposeFunc(f, name);

            if (exposedF) {
                funcVector.push_back(static_cast<void *>(exposedF));

                initMap.insert(std::pair<char *, char *>(strdup(name.c_str()), strdup(exposedF->toString().c_str())));
                std::string r = "/callfunc_";
                r.append(name);
                callFromPost(r.c_str(), [exposedF](std::string req_body) {
                    return Caller::call(exposedF, req_body);
                });
            } else {
                _errorF("[CppJsLib] Cannot expose function " + name + ": Unable to allocate memory");
            }
        }

        template<class R, class...Args>
        inline void _exportFunction(R(*f)(Args...), std::string name) {
            _loggingF("[CppJsLib] Exposing function with name " + name);
            if (running) {
                _errorF("[CppJsLib] Cannot expose function " + name + " since the web server is already running");
                return;
            }
            auto exposedF = _exposeFunc(f, name);

            if (exposedF) {
                funcVector.push_back(static_cast<void *>(exposedF));

                initMap.insert(std::pair<char *, char *>(strdup(name.c_str()), strdup(exposedF->toString().c_str())));
                std::string r = "/callfunc_";
                r.append(name);
                callFromPost(r.c_str(), [exposedF](std::string req_body) {
                    return Caller::call(exposedF, req_body);
                });
            } else {
                _errorF("[CppJsLib] Cannot expose function " + name + ": Unable to allocate memory");
            }
        }

#ifdef CPPJSLIB_ENABLE_WEBSOCKET

        CPPJSLIB_EXPORT void
        call_jsFn(std::vector<std::string> *argV, const char *funcName, std::vector<char *> *results = nullptr,
                  int wait = -1);

        template<class...Args>
        inline void _importJsFunction(std::function<void(Args...)> *function, std::string fName) {
            if (fName[0] == '&') {
                fName.erase(0, 1); // Delete first character as it is a &
            }

            _loggingF("[CppJsLib] Importing js function with name " + fName);
#ifndef CPPJSLIB_ENABLE_HTTPS
            bool ssl = false;
#endif
            auto *f = new(std::nothrow) struct JsFunction<void(Args...)>(fName, std::shared_ptr<WebGUI>(this));
            if (f != nullptr) {
                jsFuncVector.push_back(static_cast<void *>(f));
                *function = [f](Args...args) {
                    f->operator()(args...);
                };
            } else {
                _errorF("[CppJsLib] Could not import function " + fName + ": Unable to allocate memory");
            }
        }

        template<class R, class...Args>
        inline void
        _importJsFunction(std::function<std::vector<R>(Args...)> *function, std::string fName, int waitS = -1) {
            if (fName[0] == '&') {
                fName.erase(0, 1); // Delete first character as it is a &
            }

            _loggingF("[CppJsLib] Importing js function with name " + fName);
#ifndef CPPJSLIB_ENABLE_HTTPS
            bool ssl = false;
#endif
            auto *f = new(std::nothrow) struct JsFunction<std::vector<R>(Args...)>(fName, std::shared_ptr<WebGUI>(this),
                                                                                   waitS);
            if (f != nullptr) {
                jsFuncVector.push_back(static_cast<void *>(f));
                *function = [f](Args...args) {
                    return f->operator()(args...);
                };
            } else {
                _errorF("[CppJsLib] Could not import function " + fName + ": Unable to allocate memory");
            }
        }

#endif

        CPPJSLIB_EXPORT bool start(int port, CPPJSLIB_WS_PORT const std::string &host = "localhost", bool block = true);

        CPPJSLIB_EXPORT void setLogger(std::function<void(const std::string &)> loggingFunction);

        CPPJSLIB_EXPORT void setError(std::function<void(const std::string &)> errorFunction);

        /**
         * A function used by the getHttpServer macro
         *
         * @warning Please DO NOT USE this function
         * @tparam T the param to convert the server pointer to, MUST be httplib::Server* or httplib::SSLServer*
         * @return a pointer to the http Server of this instance
         */
        template<typename T>
        inline std::shared_ptr<T> _getHttpServer() {
            return std::static_pointer_cast<T>(server);
        }

#ifdef CPPJSLIB_ENABLE_WEBSOCKET

#ifdef CPPJSLIB_ENABLE_HTTPS

        template<typename T>
        inline std::shared_ptr<T> _getTLSWebServer() {
            return std::static_pointer_cast<T>(ws_server);
        }

#endif

        template<typename T>
        inline std::shared_ptr<T> _getWebServer() {
            if (fallback_plain) {
                return std::static_pointer_cast<T>(ws_plain_server);
            } else {
                return std::static_pointer_cast<T>(ws_server);
            }
        }

#endif

        CPPJSLIB_EXPORT ~WebGUI();

        bool running;
        bool stopped;
#ifdef CPPJSLIB_ENABLE_HTTPS
        const bool ssl;
        const unsigned short fallback_plain;
#endif
    private:
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
        std::shared_ptr<void> ws_server;
        std::shared_ptr<void> ws_plain_server;
        std::shared_ptr<void> ws_connections;
        std::shared_ptr<void> ws_plain_connections;
#endif
        std::shared_ptr<void> server;
        std::map<char *, char *> initMap;
        std::vector<void *> funcVector;
        std::vector<void *> jsFuncVector;
        using PostHandler = std::function<std::string(std::string req_body)>;
        std::function<void(const std::string &)> _loggingF;
        std::function<void(const std::string &)> _errorF;

        CPPJSLIB_EXPORT void callFromPost(const char *target, const PostHandler &handler);
    };

    CPPJSLIB_EXPORT bool stop(WebGUI *webGui, bool block = true, int maxWaitSeconds = CPPJSLIB_DURATION_INFINITE);
}

#endif //CPPJSLIB_WEBGUI_HPP
