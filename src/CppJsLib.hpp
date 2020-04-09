#ifndef CPPJSLIB_WEBGUI_HPP
#define CPPJSLIB_WEBGUI_HPP

#ifdef CPPJSLIB_ENABLE_HTTPS
#   define CPPHTTPLIB_OPENSSL_SUPPORT
#else
#   undef CPPHTTPLIB_OPENSSL_SUPPORT
#   undef CPPJSLIB_ENABLE_HTTPS //Redundant, just adding this so CLion recognizes this macro as existing
#endif //CPPJSLIB_ENABLE_HTTPS

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)
#   define CPPJSLIB_WINDOWS
#   undef CPPJSLIB_UNIX
#elif defined(__LINUX__) || defined(__APPLE__) || defined (__CYGWIN__) || defined(__linux__)
#   define CPPJSLIB_UNIX
#   undef CPPJSLIB_WINDOWS
#endif

#if (defined(CPPJSLIB_STATIC_DEFINE) && !defined (CPPJSLIB_BUILD_LIB)) || defined (CPPJSLIB_UNIX)
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

#include <functional>
#include <sstream>
#include <cstring>
#include <map>
#include <utility>
#include <vector>
#include <iostream>
#include <memory>

#ifdef CPPJSLIB_WINDOWS
#   define strdup _strdup
#   define strcpy strcpy_s
#endif //CPPJSLIB_WINDOWS

#define expose(func) _exportFunction(func, #func)
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
#   define importFunction(func, ...) _importJsFunction(func, #func, ##__VA_ARGS__)
#   define getWebServer() _getWebServer<websocketpp::server<websocketpp::config::asio>>()
#   ifdef CPPJSLIB_ENABLE_HTTPS
#       define getTLSWebServer() _getTLSWebServer<websocketpp::server<websocketpp::config::asio_tls>>()
#   endif //CPPJSLIB_ENABLE_HTTPS
#endif //CPPJSLIB_ENABLE_WEBSOCKET

#ifdef CPPJSLIB_ENABLE_HTTPS
#   define getHttpsServer() _getHttpServer<httplib::SSLServer>()
#endif //CPPJSLIB_ENABLE_HTTPS

#define getHttpServer() _getHttpServer<httplib::Server>()

#define CPPJSLIB_DURATION_INFINITE -1
#define CPPJSLIB_MAX_FUNCNAME_LEN 250

namespace CppJsLib {
    const char localhost[] = "127.0.0.1";

    class WebGUI;

    namespace util {
        CPPJSLIB_EXPORT std::string *parseJSONInput(int *size, const std::string &args);

        CPPJSLIB_EXPORT std::string stringArrayToJSON(std::vector<std::string> *v);

        CPPJSLIB_EXPORT std::string stringToJSON(std::string s);

        CPPJSLIB_EXPORT std::string *createStringArrayFromJSON(int *size, const std::string &data);

        CPPJSLIB_EXPORT void pushToStrVecVector(WebGUI *webGui, std::vector<char *> *v);

        CPPJSLIB_EXPORT void pushToVoidPtrVector(WebGUI *webGui, void *ptr);

        template<class>
        struct TypeConverter;

        template<class>
        struct cString;

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

        CPPJSLIB_EXPORT void
        callJsFunc(WebGUI *wGui, std::vector<std::string> *argV, char *funcName,
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
            void operator()() {
                std::vector<std::string> argV;
                callJsFunc(wGui, &argV, fnName);
            }

            char fnName[CPPJSLIB_MAX_FUNCNAME_LEN];
            WebGUI *wGui;
        };

        template<class... Args>
        struct JsFunction<void(Args ...)> {
            void operator()(Args ... args) {
                std::vector<std::string> argV;
                auto x = {(ConvertToString(&argV, getEl(args)), 0)...};
                callJsFunc(wGui, &argV, fnName);
            }

            char fnName[CPPJSLIB_MAX_FUNCNAME_LEN];
            WebGUI *wGui;
        };

        template<class R>
        struct JsFunction<std::vector<R>()> {
            std::vector<R> operator()() {
                std::vector<std::string> argV;
                callJsFunc(wGui, &argV, fnName, responseReturns, wait);

                std::vector<R> tmp;
                for (char *c : *responseReturns) {
                    tmp.push_back(ConvertString<R>(c));
                    free(c);
                }
                std::vector<char *>().swap(*responseReturns);

                return tmp;
            }

            char fnName[CPPJSLIB_MAX_FUNCNAME_LEN] = "";
            int wait = -1;
            WebGUI *wGui = nullptr;
            std::vector<char *> *responseReturns = nullptr;
        };

        template<class R, class... Args>
        struct JsFunction<std::vector<R>(Args ...)> {
            std::vector<R> operator()(Args ... args) {
                std::vector<std::string> argV;
                auto x = {(ConvertToString(&argV, getEl(args)), 0)...};
                callJsFunc(wGui, &argV, fnName, responseReturns, wait);

                std::vector<R> tmp;
                for (char *c : *responseReturns) {
                    tmp.push_back(ConvertString<R>(c));
                    free(c);
                }
                std::vector<char *>().swap(*responseReturns);

                return tmp;
            }

            char fnName[CPPJSLIB_MAX_FUNCNAME_LEN] = "";
            int wait = -1;
            WebGUI *wGui = nullptr;
            std::vector<char *> *responseReturns = nullptr;
        };

        template<class ...Args>
        inline void initJsFunction(JsFunction<void(Args...)> **toInit, std::string name, WebGUI *_wGui) {
            auto *tmp = (JsFunction<void(Args...)> *) malloc(sizeof(JsFunction<void(Args...)>));
            if (tmp) {
                strcpy(tmp->fnName, name.c_str());
                tmp->wGui = _wGui;
            }

            *toInit = tmp;
        }

        template<class R, class... Args>
        inline void
        initJsFunction(JsFunction<std::vector<R>(Args ...)> **toInit, std::string name, WebGUI *_wGui,
                       int waitS) {
            auto *tmp = (JsFunction<std::vector<R>(Args ...)> *) malloc(sizeof(JsFunction<std::vector<R>(Args ...)>));
            if (tmp) {
                strcpy(tmp->fnName, name.c_str());
                tmp->wGui = _wGui;
                tmp->wait = waitS;

                tmp->responseReturns = new std::vector<char *>();
                pushToStrVecVector(_wGui, tmp->responseReturns);
            }

            *toInit = tmp;
        }

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

        template<>
        struct TypeConverter<std::string> {
            static std::string toString(std::string toConvert) {
                return toConvert;
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

        template<>
        struct cString<std::string> {
            static std::string convert(const std::string &data) {
                return data;
            }
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
                f(ConvertString<Args>(args[S])...);
            }

            std::string toString() {
                return fnString;
            }

            char *fnString = nullptr;

            void (*f)(Args...) = nullptr;
        };

        template<class R, class... Args>
        struct ExposedFunction<R(Args...)> {
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
                return f(ConvertString<Args>(args[S])...);
            }

            std::string toString() {
                return fnString;
            }

            char *fnString = nullptr;

            R (*f)(Args...) = nullptr;
        };

        template<class R, class ...Args>
        void initExposedFunction(ExposedFunction<R(Args...)> **toInit, R (*f)(Args...), const std::string &name,
                                 WebGUI *wGui) {
            auto *tmp = (ExposedFunction<R(Args...)> *) malloc(sizeof(ExposedFunction<R(Args...)>));
            if (tmp) {
                typedef function_traits<std::function<R(Args...)>> fn_traits;
                auto *types = new(std::nothrow) std::string[fn_traits::nargs];
                if (!types) {
                    free(tmp);
                    *toInit = nullptr;
                    return;
                }
                expose_helper<std::function<R(Args...)>, fn_traits::nargs>::__expose(types);

                std::string fnString = getTypeName<R>();
                fnString.append(" ").append(name).append("(");
                for (int i = 0; i < fn_traits::nargs; i++) {
                    if (i > 0) fnString.append(", ");
                    fnString.append(types[i]);
                }
                fnString.append(")");

                delete[] types;

                tmp->fnString = strdup(fnString.c_str());
                pushToVoidPtrVector(wGui, static_cast<void *>(tmp->fnString));
                tmp->f = f;
            }

            *toInit = tmp;
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
    }

    CPPJSLIB_EXPORT void setLogger(const std::function<void(const std::string &)> &loggingFunction);

    CPPJSLIB_EXPORT void setError(const std::function<void(const std::string &)> &errorFunction);

#if defined(CPPJSLIB_BUILD_LIB) || !defined (CPPJSLIB_STATIC_DEFINE)

#   ifdef CPPJSLIB_ENABLE_HTTPS

    CPPJSLIB_EXPORT void createWebGUI(WebGUI *&webGui, const std::string &base_dir, const std::string &cert_path,
                                      const std::string &private_key_path,
                                      unsigned short websocket_plain_fallback_port = 0);

#   endif //CPPJSLIB_ENABLE_HTTPS

    CPPJSLIB_EXPORT void createWebGUI(WebGUI *&webGui, const std::string &base_dir);

    CPPJSLIB_EXPORT void deleteWebGUI(WebGUI *&webGui);

#endif //defined(CPPJSLIB_BUILD_LIB) || !defined (CPPJSLIB_STATIC_DEFINE)

    class WebGUI {
    public:
        // Delete any constructor not allowed to initialize everything correctly
        // and to prevent heap corruptions to occur
        WebGUI() = delete;

        WebGUI(const WebGUI &) = delete;

        WebGUI &operator=(const WebGUI &) = delete;

#ifdef CPPJSLIB_STATIC_DEFINE
#   ifdef CPPJSLIB_ENABLE_HTTPS

        /**
         * @warning this constructor will be undeclared when built without ssl support
         */
        WebGUI(const std::string &base_dir, const std::string &cert_path,
               const std::string &private_key_path, unsigned short websocket_plain_fallback_port = 0);

#   endif //CPPJSLIB_ENABLE_HTTPS

        explicit WebGUI(const std::string &base_dir);

#endif //CPPJSLIB_STATIC_DEFINE

#ifdef CPPJSLIB_BUILD_JNI_DLL
        void exportJavaFunction(const std::string& name, std::string returnType, std::string *argTypes, int numArgs,
                                const std::function<std::string(std::string *, int)> &fn);
#endif //CPPJSLIB_BUILD_JNI_DLL

        template<class...Args>
        inline void _exportFunction(void(*f)(Args...), std::string name) {
            this->log("[CppJsLib] Exposing void function with name " + name);
            if (running) {
                this->err("[CppJsLib] Cannot expose function " + name + " since the web server is already running");
                return;
            }
            util::ExposedFunction<void(Args...)> *exposedF = nullptr;
            util::initExposedFunction(&exposedF, f, name, this);

            if (exposedF) {
                this->pushToVoidPtrVector(static_cast<void *>(exposedF));

                this->insertToInitMap(strdup(name.c_str()), strdup(exposedF->toString().c_str()));
                std::string r = "/callfunc_";
                r.append(name);

                callFromPost(r.c_str(), [exposedF](std::string req_body) {
                    return util::Caller::call(exposedF, req_body);
                });
            } else {
                this->err("[CppJsLib] Cannot expose function " + name + ": Unable to allocate memory");
            }
        }

        template<class R, class...Args>
        inline void _exportFunction(R(*f)(Args...), std::string name) {
            this->log("[CppJsLib] Exposing function with name " + name);
            if (running) {
                this->err("[CppJsLib] Cannot expose function " + name + " since the web server is already running");
                return;
            }
            util::ExposedFunction<R(Args...)> *exposedF;
            util::initExposedFunction(&exposedF, f, name, this);

            if (exposedF) {
                this->pushToVoidPtrVector(static_cast<void *>(exposedF));

                this->insertToInitMap(strdup(name.c_str()), strdup(exposedF->toString().c_str()));
                std::string r = "/callfunc_";
                r.append(name);

                callFromPost(r.c_str(), [exposedF](std::string req_body) {
                    return util::Caller::call(exposedF, req_body);
                });
            } else {
                this->err("[CppJsLib] Cannot expose function " + name + ": Unable to allocate memory");
            }
        }

#ifdef CPPJSLIB_ENABLE_WEBSOCKET

        CPPJSLIB_EXPORT void
        call_jsFn(std::vector<std::string> *argV, const char *funcName,
                  std::vector<char *> *results = nullptr, int wait = -1);

        template<class...Args>
        inline void _importJsFunction(std::function<void(Args...)> &function, std::string fName) {
            if (fName[0] == '*') {
                fName.erase(0, 1); // Delete first character as it is a *
            }

            this->log("[CppJsLib] Importing js function with name " + fName);
            util::JsFunction<void(Args...)> *f = nullptr;
            util::initJsFunction(&f, fName, this);

            if (f != nullptr) {
                auto *a = static_cast<void *>(&(*f));
                this->pushToVoidPtrVector(a);
                function = [f](Args...args) {
                    f->operator()(args...);
                };
            } else {
                this->err("[CppJsLib] Could not import function " + fName + ": Unable to allocate memory");
            }
        }

        template<class R, class...Args>
        inline void
        _importJsFunction(std::function<std::vector<R>(Args...)> &function, std::string fName, int waitS = -1) {
            if (fName[0] == '&') {
                fName.erase(0, 1); // Delete first character as it is a &
            }

            this->log("[CppJsLib] Importing js function with name " + fName);
            util::JsFunction<std::vector<R>(Args...)> *f = nullptr;
            util::initJsFunction(&f, fName, this, waitS);

            if (f != nullptr) {
                this->pushToVoidPtrVector(static_cast<void *>(f));
                function = [f](Args...args) {
                    return f->operator()(args...);
                };
            } else {
                _errorF("[CppJsLib] Could not import function " + fName + ": Unable to allocate memory");
            }
        }

        CPPJSLIB_EXPORT bool
        start(int port, int websocketPort, const std::string &host = "localhost", bool block = true);

#else
        CPPJSLIB_EXPORT bool start(int port, const std::string &host = "localhost", bool block = true);
#endif //CPPJSLIB_ENABLE_WEBSOCKET

        CPPJSLIB_EXPORT void setLogger(const std::function<void(const std::string &)> &loggingFunction);

        CPPJSLIB_EXPORT void setError(const std::function<void(const std::string &)> &errorFunction);

        CPPJSLIB_EXPORT void pushToVoidPtrVector(void *f);

        CPPJSLIB_EXPORT void pushToStrVecVector(std::vector<char *> *v);

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

        CPPJSLIB_EXPORT void setWebSocketOpenHandler(const std::function<void()> &handler);

        CPPJSLIB_EXPORT void setWebSocketCloseHandler(const std::function<void()> &handler);

#   ifdef CPPJSLIB_ENABLE_HTTPS

        template<typename T>
        inline std::shared_ptr<T> _getTLSWebServer() {
            return std::static_pointer_cast<T>(ws_server);
        }

#   endif //CPPJSLIB_ENABLE_HTTPS

        template<typename T>
        inline std::shared_ptr<T> _getWebServer() {
#   ifdef CPPJSLIB_ENABLE_HTTPS
            if (fallback_plain) {
                return std::static_pointer_cast<T>(ws_plain_server);
            } else {
#   endif //CPPJSLIB_ENABLE_HTTPS
                return std::static_pointer_cast<T>(ws_server);
#   ifdef CPPJSLIB_ENABLE_HTTPS
            }
#   endif //CPPJSLIB_ENABLE_HTTPS
        }

#endif //CPPJSLIB_ENABLE_WEBSOCKET

// Delete default destructor if the dll is used to prevent heap corruption
#ifndef CPPJSLIB_STATIC_DEFINE
        ~WebGUI() = delete;
#else

        ~WebGUI();

#endif //CPPJSLIB_STATIC_DEFINE

        bool check_ports;
        bool running;
        bool stopped;
#ifdef CPPJSLIB_ENABLE_HTTPS
        const bool ssl;
        const unsigned short fallback_plain;
#endif //CPPJSLIB_ENABLE_HTTPS
    private:
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
        std::shared_ptr<void> ws_server;
        std::shared_ptr<void> ws_connections;
#   ifdef CPPJSLIB_ENABLE_HTTPS
        std::shared_ptr<void> ws_plain_server;
        std::shared_ptr<void> ws_plain_connections;
#   endif //CPPJSLIB_ENABLE_HTTPS
#endif //CPPJSLIB_ENABLE_WEBSOCKET
        std::shared_ptr<void> server;

        std::map<char *, char *> initMap;
        std::vector<void *> voidPtrVector;
        std::vector<std::vector<char *> *> strVecVector;

        using PostHandler = std::function<std::string(std::string req_body)>;
        std::function<void(const std::string &)> _loggingF;
        std::function<void(const std::string &)> _errorF;

        CPPJSLIB_EXPORT void callFromPost(const char *target, const PostHandler &handler);

        CPPJSLIB_EXPORT void log(const std::string &msg);

        CPPJSLIB_EXPORT void err(const std::string &msg);

        CPPJSLIB_EXPORT void insertToInitMap(char *name, char *exposedFStr);
    };

    CPPJSLIB_EXPORT bool stop(WebGUI *webGui, bool block = true, int maxWaitSeconds = CPPJSLIB_DURATION_INFINITE);

    CPPJSLIB_EXPORT bool ok();

    CPPJSLIB_EXPORT std::string getLastError();

    CPPJSLIB_EXPORT void resetLastError();
}

#endif //CPPJSLIB_WEBGUI_HPP
