#ifndef CPPJSLIB_WEBGUI_HPP
#define CPPJSLIB_WEBGUI_HPP

#if __cplusplus >= 201603L
#   define CPPJSLIB_MAYBE_UNUSED [[maybe_unused]]
#   define CPPJSLIB_NODISCARD [[nodiscard]]
#else
#   define CPPJSLIB_MAYBE_UNUSED
#   define CPPJSLIB_NODISCARD
#endif

#ifdef CPPJSLIB_ENABLE_HTTPS
#   define CPPHTTPLIB_OPENSSL_SUPPORT
#else
#   undef CPPHTTPLIB_OPENSSL_SUPPORT
#   undef CPPJSLIB_ENABLE_HTTPS //Redundant, just adding this so CLion recognizes this macro as existing
#endif //CPPJSLIB_ENABLE_HTTPS

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)
#   define CPPJSLIB_WINDOWS
#   undef CPPJSLIB_UNIX
#elif defined(__LINUX__) || defined(__APPLE__) || defined (__CYGWIN__) || defined(__linux__) || defined(__FreeBSD__) || defined(unix) || defined(__unix) || defined(__unix__)
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
#include <atomic>
#include <mutex>

#ifdef CPPJSLIB_WINDOWS
#   define strdup _strdup
#   define strcpy strcpy_s
#endif //CPPJSLIB_WINDOWS

#define expose(func) _exportFunction(func, #func)
#define import(func, ...) _importJsFunction(func, #func, ##__VA_ARGS__)

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
#   define getWebServer() _getWebServer<websocketpp::server<websocketpp::config::asio>>()
#   ifdef CPPJSLIB_ENABLE_HTTPS
#       define getTLSWebServer() _getTLSWebServer<websocketpp::server<websocketpp::config::asio_tls>>()
#   endif //CPPJSLIB_ENABLE_HTTPS
#else
#   undef CPPJSLIB_ENABLE_WEBSOCKET
#endif //CPPJSLIB_ENABLE_WEBSOCKET

#ifdef CPPJSLIB_ENABLE_HTTPS
#   define getHttpsServer() _getHttpServer<httplib::SSLServer>()
#else
#   undef CPPJSLIB_ENABLE_HTTPS
#endif //CPPJSLIB_ENABLE_HTTPS

#define getHttpServer() _getHttpServer<httplib::Server>()

#define CPPJSLIB_DURATION_INFINITE -1
#define CPPJSLIB_MAX_FUNCNAME_LEN 250

/**
 * Main CppJsLib namespace
 */
namespace CppJsLib {
    /**
     * @brief Localhost IP
     */
    const char localhost[] = "127.0.0.1";

    class WebGUI;

    /**
     * Utility namespace. Containing dependencies for WebGUI
     */
    namespace util {
        namespace logging {
            CPPJSLIB_EXPORT void log(const std::string &message);

            CPPJSLIB_EXPORT void err(const std::string &message);
        }

        /**
         * Exception namespace
         */
        namespace exception {
            /**
             * Thrown when the given argument count does not match
             */
            class ArgumentCountDoesNotMatchException : std::exception {
            public:
                /**
                 * Thrown when the given argument count does not match
                 */
                ArgumentCountDoesNotMatchException() : std::exception() {}
            };

            /**
             * Thrown when a value cannot be converted
             */
            class ConversionException : std::exception {
            public:
                /**
                 * No default constructor
                 */
                ConversionException() = delete;

                /**
                * Thrown when a value cannot be converted
                */
                explicit ConversionException(std::string _err) : std::exception() {
                    err = std::move(_err);
                }

                /**
                 * Get the exception message
                 *
                 * @return the exception message
                 */
                const char *what() {
                    return err.c_str();
                }

            private:
                std::string err;
            };
        }

        CPPJSLIB_EXPORT std::vector<std::string> parseJSONInput(const std::string &args);

        CPPJSLIB_EXPORT std::string stringArrayToJSON(const std::vector<std::string> &v);

        CPPJSLIB_EXPORT std::string stringMapToJSON(const std::map<std::string, std::string> &m);

        CPPJSLIB_EXPORT std::string stringToJSON(const std::string &s);

        CPPJSLIB_EXPORT std::vector<std::string> createStringArrayFromJSON(const std::string &data);

        CPPJSLIB_EXPORT std::map<std::string, std::string> createStringMapFromJSON(const std::string &data);

        CPPJSLIB_EXPORT void pushToStrVecVector(WebGUI *webGui, std::vector<std::string> *v);

        CPPJSLIB_EXPORT void pushToVoidPtrVector(WebGUI *webGui, void *ptr);

#ifndef CPPJSLIB_ENABLE_WEBSOCKET
        CPPJSLIB_EXPORT void pushToSseVector(WebGUI *webGui, const std::string &s);
#endif

        template<class>
        struct CPPJSLIB_MAYBE_UNUSED TypeConverter;

        /**
         * A struct to convert a std::map to a string or JSON string
         *
         * @tparam K the map key type
         * @tparam T the map type type
         */
        template<class K, class T>
        struct TypeConverter<std::map<K, T>> {
            /**
             * Convert a map to a JSON string
             *
             * @param toConvert the map to convert
             * @return the JSON string
             */
            CPPJSLIB_MAYBE_UNUSED static std::string toJsonString(std::map<K, T> toConvert) {
                std::map<std::string, std::string> stringMap;
                for (std::pair<K, T> p : toConvert) {
                    stringMap.insert(std::pair<std::string, std::string>(TypeConverter<K>::toString(p.first),
                                                                         TypeConverter<T>::toString(p.second)));
                }

                std::string res = stringMapToJSON(stringMap);
                std::map<std::string, std::string>().swap(stringMap);
                return res;
            }

            /**
             * Convert a map to a JSON string
             *
             * @warning returns a JSON string
             * @param toConvert the map to convert
             * @return the JSON string
             */
            CPPJSLIB_MAYBE_UNUSED static std::string toString(const std::map<K, T> &toConvert) {
                return toJsonString(toConvert);
            }
        };

        /**
         * A struct to convert a std::vector to a string or JSON string
         *
         * @tparam T the vector type
         */
        template<class T>
        struct TypeConverter<std::vector<T>> {
            /**
             * Convert a vector to a JSON string
             *
             * @param toConvert the vector
             * @return the resulting JSON string
             */
            CPPJSLIB_MAYBE_UNUSED static std::string toJsonString(std::vector<T> toConvert) {
                std::vector<std::string> stringVector(toConvert.size());
                for (T val : toConvert) {
                    stringVector.push_back(TypeConverter<T>::toString(val));
                }

                std::string res = stringArrayToJSON(stringVector);
                std::vector<std::string>().swap(stringVector);
                return res;
            }

            /**
             * Convert a vector to a JSON string
             *
             * @warning returns a JSON string
             * @param toConvert the vector
             * @return the resulting JSON string
             */
            CPPJSLIB_MAYBE_UNUSED static std::string toString(const std::vector<T> &toConvert) {
                return toJsonString(toConvert);
            }
        };

        /**
         * A struct to convert types to a string or JSON string
         */
        template<>
        struct TypeConverter<std::string> {
            /**
             * Convert a string to a JSON string
             *
             * @param toConvert the string to convert
             * @return the resulting JSON string
             */
            CPPJSLIB_MAYBE_UNUSED static std::string toJsonString(const std::string &toConvert) {
                return stringToJSON(toConvert);
            }

            /**
             * Convert a string to a string
             *
             * @param toConvert the input string
             * @return the same as the input string
             */
            CPPJSLIB_MAYBE_UNUSED static std::string toString(std::string toConvert) {
                return toConvert;
            }
        };

        /**
         * A struct to convert types to a string or JSON string
         *
         * @tparam T the type
         */
        template<class T>
        struct TypeConverter {
            /**
             * Convert type to JSON string
             *
             * @param toConvert the value to convert
             * @return the resulting JSON string
             */
            CPPJSLIB_MAYBE_UNUSED static std::string toJsonString(T toConvert) {
                return stringToJSON(std::to_string(toConvert));
            }

            /**
             * Convert type to string
             *
             * @param toConvert the value to convert
             * @return the resulting string
             */
            CPPJSLIB_MAYBE_UNUSED static std::string toString(T toConvert) {
                return std::to_string(toConvert);
            }
        };

        /**
         * Stop the web server
         * Do not use this. Or use it at your own risk
         *
         * @param webGui the webGui object to stop
         * @param block if this is a blocking call
         * @param maxWaitSeconds a max number of seconds to wait
         * @return if the operation was successful
         */
        CPPJSLIB_EXPORT bool stop(WebGUI *webGui, bool block = true, int maxWaitSeconds = CPPJSLIB_DURATION_INFINITE);

        template<class>
        struct CPPJSLIB_MAYBE_UNUSED cString;

        template<class>
        struct ExposedFunction;

        template<typename T>
        struct function_traits;

        template<class R>
        std::string getTypeName();

        template<typename T>
        T ConvertString(const std::string &data);

        template<class>
        struct JsFunction;

        CPPJSLIB_EXPORT void
        callJsFunc(WebGUI *wGui, std::vector<std::string> *argV, char *funcName,
                   std::vector<std::string> *results = nullptr, int wait = -1);

        /**
         * Convert a type to string, accepts basic types, std::vector and std::map
         *
         * @tparam T the type
         * @param data the data to convert
         * @return the resulting string
         */
        template<typename T>
        inline std::string convertToString(T data) {
            return TypeConverter<T>::toString(data);
        }

        /**
         * Convert a vararg list to a string vector
         *
         * @tparam Args the argument types
         * @param argV the string vector to populate
         * @param args the arguments to convert
         */
        template<class ...Args>
        inline void ConvertToStringVector(std::vector<std::string> argV, Args...args) {
            // Use volatile to disable optimization
            CPPJSLIB_MAYBE_UNUSED volatile auto x = {(argV.push_back(args), 0)...};
        }

        /**
         * A struct for js function
         */
        template<>
        struct JsFunction<void()> {
            /**
             * The operator() to call the js function
             */
            void operator()() {
                std::vector<std::string> argV;
                callJsFunc(wGui, &argV, fnName);
            }

            char fnName[CPPJSLIB_MAX_FUNCNAME_LEN];
            WebGUI *wGui;
        };

        /**
         * A struct for js function
         *
         * @tparam Args the function arguments
         */
        template<class... Args>
        struct JsFunction<void(Args ...)> {
            /**
             * The operator() to call the function
             *
             * @param args the arguments
             */
            void operator()(Args ... args) {
                std::vector<std::string> argV;
                CPPJSLIB_MAYBE_UNUSED volatile auto x = {(ConvertToStringVector(argV, convertToString(args)), 0)...};
                callJsFunc(wGui, &argV, fnName);
            }

            char fnName[CPPJSLIB_MAX_FUNCNAME_LEN];
            WebGUI *wGui;
        };

        /**
         * Initialize a imported void js function
         *
         * @tparam Args the arg types
         * @param toInit the JsFunction struct to init
         * @param name the function name
         * @param _wGui a WebGUI instance
         */
        template<class ...Args>
        inline void initJsFunction(JsFunction<void(Args...)> **toInit, const std::string &name, WebGUI *_wGui) {
            auto *tmp = (JsFunction<void(Args...)> *) malloc(sizeof(JsFunction<void(Args...)>));
            if (tmp) {
                strcpy(tmp->fnName, name.c_str());
                tmp->wGui = _wGui;
            }

            *toInit = tmp;
#ifndef CPPJSLIB_ENABLE_WEBSOCKET
            pushToSseVector(_wGui, name);
#endif //CPPJSLIB_ENABLE_WEBSOCKET
        }

#ifdef CPPJSLIB_ENABLE_WEBSOCKET

/**
         * A struct for js function
         *
         * @tparam R the function return type
         */
        template<class R>
        struct JsFunction<std::vector<R>()> {
            /**
             * The operator() to call the js function
             *
             * @return the returns as all clients as a vector
             */
            std::vector<R> operator()() {
                std::vector<std::string> argV;
                callJsFunc(wGui, &argV, fnName, responseReturns, wait);

                std::vector<R> tmp;
                for (std::string c : *responseReturns) {
                    tmp.push_back(ConvertString<R>(c));
                }
                std::vector<std::string>().swap(*responseReturns);

                return tmp;
            }

            char fnName[CPPJSLIB_MAX_FUNCNAME_LEN] = "";
            int wait = -1;
            WebGUI *wGui = nullptr;
            std::vector<std::string> *responseReturns = nullptr;
        };

        /**
         * A struct for js function
         *
         * @tparam R the function return type
         * @tparam Args the function arguments
         */
        template<class R, class... Args>
        struct JsFunction<std::vector<R>(Args ...)> {
            /**
             * The operator() to call the function
             *
             * @param args the function arguments
             * @return the returns of all clients as a vector
             */
            std::vector<R> operator()(Args ... args) {
                std::vector<std::string> argV;
                CPPJSLIB_MAYBE_UNUSED volatile auto x = {(ConvertToStringVector(argV, convertToString(args)), 0)...};
                callJsFunc(wGui, &argV, fnName, responseReturns, wait);

                std::vector<R> tmp;
                for (std::string c : *responseReturns) {
                    tmp.push_back(ConvertString<R>(c));
                }
                std::vector<std::string>().swap(*responseReturns);

                return tmp;
            }

            char fnName[CPPJSLIB_MAX_FUNCNAME_LEN] = "";
            int wait = -1;
            WebGUI *wGui = nullptr;
            std::vector<std::string> *responseReturns = nullptr;
        };

        /**
         * Initialize a imported js function
         *
         * @tparam R the function return type
         * @tparam Args the argument types
         * @param toInit the struct to init
         * @param name the function name
         * @param _wGui a WebGUI instance
         * @param waitS a timout in seconds
         */
        template<class R, class... Args>
        inline void
        initJsFunction(JsFunction<std::vector<R>(Args ...)> **toInit, const std::string &name, WebGUI *_wGui,
                       int waitS) {
            // Allocate the JsFunction struct
            auto *tmp = (JsFunction<std::vector<R>(Args ...)> *) malloc(sizeof(JsFunction<std::vector<R>(Args ...)>));
            if (tmp) {
                strcpy(tmp->fnName, name.c_str());
                tmp->wGui = _wGui;
                tmp->wait = waitS;

                tmp->responseReturns = new std::vector<std::string>();
                pushToStrVecVector(_wGui, tmp->responseReturns);
            }

            *toInit = tmp;
        }

#endif

        template<typename R, typename ...Args>
        struct function_traits<std::function<R(Args...)>> {
            static const size_t nargs = sizeof...(Args);

            template<size_t i>
            struct arg {
                typedef typename std::tuple_element<i, std::tuple<Args...>>::type type;
            };
        };

        /**
         * A struct to convert a type name to a string, accepts basic types, std::map and std::vector
         */
        template<typename>
        struct CPPJSLIB_MAYBE_UNUSED Types;

        /**
         * A struct to get the type name as string from a type
         *
         * @tparam type the type
         */
        template<typename type>
        struct Types {
            /**
             * get the type name as string
             *
             * @return the type name string
             */
            CPPJSLIB_MAYBE_UNUSED static std::string _getTypeName() {
                using namespace std;
                // Check if the type is supported
                static_assert(
                        is_same<int, type>::value || is_same<std::vector<int>, type>::value ||
                        is_same<char, type>::value ||
                        is_same<std::vector<char>, type>::value || is_same<string, type>::value ||
                        is_same<std::vector<string>, type>::value || is_same<bool, type>::value ||
                        is_same<std::vector<bool>, type>::value || is_same<float, type>::value ||
                        is_same<std::vector<float>, type>::value || is_same<double, type>::value ||
                        is_same<std::vector<double>, type>::value || std::is_same<void, type>::value,
                        "Unsupported type used");

                if (std::is_same<int, type>::value) {
                    return "int";
                } else if (std::is_same<std::vector<int>, type>::value) {
                    return "int[]";
                } else if (std::is_same<char, type>::value) {
                    return "char";
                } else if (std::is_same<std::vector<char>, type>::value) {
                    return "char[]";
                } else if (std::is_same<std::string, type>::value) {
                    return "string";
                } else if (std::is_same<std::vector<std::string>, type>::value) {
                    return "string[]";
                } else if (std::is_same<bool, type>::value) {
                    return "bool";
                } else if (std::is_same<std::vector<bool>, type>::value) {
                    return "bool[]";
                } else if (std::is_same<float, type>::value) {
                    return "float";
                } else if (std::is_same<std::vector<float>, type>::value) {
                    return "float[]";
                } else if (std::is_same<double, type>::value) {
                    return "double";
                } else if (std::is_same<std::vector<double>, type>::value) {
                    return "double[]";
                } else if (std::is_same<void, type>::value) {
                    return "void";
                } else {
                    logging::err("Found unsupported type. This should not happen");
                    return "";
                }
            }
        };

        /**
         * A struct to get the type name from a map as string
         *
         * @tparam K the map key type
         * @tparam T the map type type
         */
        template<typename K, typename T>
        struct CPPJSLIB_MAYBE_UNUSED Types<std::map<K, T>> {
            /**
             * Get the type name as string
             *
             * @return the type string
             */
            CPPJSLIB_MAYBE_UNUSED static std::string _getTypeName() {
                static_assert(!std::is_pointer_v<K> && !std::is_pointer_v<T>, "Pointers are not supported");
                std::string tmp = "map<";
                tmp.append(Types<typename std::decay_t<K>>::_getTypeName()).append(",");
                tmp.append(Types<typename std::decay_t<T>>::_getTypeName()).append(">");

                return tmp;
            }
        };

        /**
         * Get a type name as string from a type
         *
         * @tparam type the type
         * @return the type string
         */
        template<typename type>
        std::string getTypeName() {
            // Get type name without const or reference qualifier
            static_assert(!std::is_pointer_v<type>, "Pointers are not supported");
            return Types<typename std::decay_t<type>>::_getTypeName();
        }

        /**
         * A struct to get the type names of a function
         *
         * @tparam fun the type
         * @tparam i the argument position (recursive call)
         */
        template<typename fun, size_t i>
        struct expose_helper {
            static void get_types(std::string *types) {
                expose_helper<fun, i - 1>::get_types(types);
                typedef typename function_traits<fun>::template arg<i - 1>::type type;

                types[i - 1] = getTypeName<type>();
            }
        };

        /**
         * A struct to get the type names of a function
         *
         * @tparam fun the type
         */
        template<typename fun>
        struct expose_helper<fun, 0> {
            static void get_types(std::string *) {}
        };

        /**
         * A struct to return a string from a string
         */
        template<>
        struct cString<std::string> {
            /**
             * Get the input string
             *
             * @param data the input
             * @return same as the output, removes leading or trailing quotation marks if exist
             */
            static std::string convert(const std::string &data) {
                // Remove leading or trailing quotation marks if exist
                if (data[0] == '\"' && data[data.size() - 1] == '\"' && data.size() >= 2) {
                    std::string dt = data;
                    dt = dt.substr(1, dt.size() - 2);
                    return dt;
                } else {
                    return data;
                }
            }
        };

        /**
         * A struct to convert a JSON string to a vector
         *
         * @tparam T the vector type
         */
        template<typename T>
        struct cString<std::vector<T>> {
            /**
             * Convert a JSON string to a vector
             *
             * @param data the JSON string
             * @return the resulting vector
             */
            static std::vector<T> convert(const std::string &data) {
                std::vector<std::string> arr = createStringArrayFromJSON(data);
                std::vector<T> tmp(arr.size());
                for (int i = 0; i < arr.size(); i++) {
                    tmp[i] = cString<T>::convert(arr[i]);
                }

                return tmp;
            }
        };

        /**
         * A struct to convert a JSON string to a map
         *
         * @tparam K the map key type
         * @tparam T the map type type
         */
        template<typename K, typename T>
        struct cString<std::map<K, T>> {
            /**
             * Convert a JSON string to a map
             *
             * @param data the JSON string
             * @return the resulting map
             */
            static std::map<K, T> convert(const std::string &data) {
                std::map<std::string, std::string> m = createStringMapFromJSON(data);
                std::map<K, T> tmp;
                for (const auto &p : m) {
                    tmp.insert(std::pair<K, T>(cString<K>::convert(p.first), cString<T>::convert(p.second)));
                }

                return tmp;
            }
        };

        /**
         * A struct to convert a string to a bool
         */
        template<>
        struct cString<bool> {
            /**
             * Convert a string to a bool
             *
             * @param data the string to convert, must be 'true' or 'false', otherwise, a ConversionException will be thrown
             * @return the resulting bool
             */
            static bool convert(const std::string &data) {
                if (data == "false") {
                    return false;
                } else if (data == "true") {
                    return true;
                } else {
                    logging::err("Convert error: cannot convert string '" + data + "' to bool");
                    throw exception::ConversionException("Cannot convert string '" + data + "' to bool");
                }
            }
        };

        /**
         * A struct to convert a string to a type
         *
         * @tparam T the type to convert to
         */
        template<class T>
        struct cString {
            /**
             * Convert data to type T
             * If the string cannot be converted a ConversionException will be thrown
             *
             * @param data the data to convert to
             * @return the resulting data as type T
             */
            static T convert(const std::string &data) {
                T ret;

                std::istringstream iss(data);
                if (data.find("0x") != std::string::npos) {
                    iss >> std::hex >> ret;
                } else {
                    iss >> std::dec >> ret;
                }

                if (iss.fail()) {
                    logging::err("Convert error: cannot convert string '" + data + "' to value");
                    throw exception::ConversionException(
                            "Cannot convert string '" + data + "' to type '" + getTypeName<T>() + "'");
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
            } else {
                return T();
            }
        }

        /**
         * A ExposedFunction struct for void functions
         *
         * @tparam Args the argument types
         */
        template<class... Args>
        struct ExposedFunction<void(Args...)> {
            /**
             * the operator() to call the function with a JSON string array
             *
             * @param argc the number of arguments
             * @param args the JSON string array
             */
            void operator()(size_t argc, std::string *args) {
                // Check if the argument count does match
                if (argc != sizeof...(Args)) {
                    logging::err("Argument count does not match: " + std::to_string(argc) + " vs. " +
                                 std::to_string(sizeof...(Args)));
                    return;
                }

                auto sequence = std::index_sequence_for<Args...>{};
                return handleImpl(sequence, args);
            }

            /**
             * Actually call the function
             *
             * @tparam S a index_sequence
             * @param args the argument array
             */
            template<std::size_t... S>
            void handleImpl(std::index_sequence<S...>, std::string *args) {
                f(ConvertString<typename std::decay_t<Args>>(args[S])...);
            }

            /**
             * Get the function as a string
             *
             * @return the function string
             */
            std::string toString() {
                return fnString;
            }

            char *fnString = nullptr;

            void (*f)(Args...) = nullptr;
        };

        /**
         * A ExposedFunction struct for non-void functions
         *
         * @tparam R the return type
         * @tparam Args the argument types
         */
        template<class R, class... Args>
        struct ExposedFunction<R(Args...)> {
            /**
             * the operator() to call the function with a JSON string array
             *
             * @param argc the number of arguments
             * @param args the JSON string array
             * @return the return value
             */
            R operator()(size_t argc, std::string *args) {
                // Check if the argument count does match
                if (argc != sizeof...(Args)) {
                    logging::err("Argument count does not match: " + std::to_string(argc) + " vs. " +
                                 std::to_string(sizeof...(Args)));
                    throw exception::ArgumentCountDoesNotMatchException();
                }

                auto sequence = std::index_sequence_for<Args...>{};
                return handleImpl(sequence, args);
            }

            /**
             * Actually call the function
             *
             * @tparam S a index_sequence
             * @param args the argument array
             * @return the resulting value
             */
            template<std::size_t... S>
            R handleImpl(std::index_sequence<S...>, std::string *args) {
                return f(ConvertString<typename std::decay_t<Args>>(args[S])...);
            }

            /**
             * Get the function as a string
             *
             * @return the function string
             */
            std::string toString() {
                return fnString;
            }

            char *fnString = nullptr;

            R (*f)(Args...) = nullptr;
        };

        /**
         * Initialize the exposedFunction struct
         *
         * @tparam R the function return type
         * @tparam Args the function argument types
         * @param toInit the exposedFunction struct to init
         * @param f the C++ function
         * @param name the function name
         * @param wGui a WebGUI instance
         */
        template<class R, class ...Args>
        void initExposedFunction(ExposedFunction<R(Args...)> **toInit, R (*f)(Args...), const std::string &name,
                                 WebGUI *wGui) {
            // Allocate the struct
            auto *tmp = (ExposedFunction<R(Args...)> *) malloc(sizeof(ExposedFunction<R(Args...)>));
            if (tmp) {
                // Use function_traits to convert the arguments to strings
                typedef function_traits<std::function<R(Args...)>> fn_traits;
                auto *types = new(std::nothrow) std::string[fn_traits::nargs];
                if (!types) {
                    free(tmp);
                    *toInit = nullptr;
                    return;
                }
                expose_helper<std::function<R(Args...)>, fn_traits::nargs>::get_types(types);

                // Create a string to match the function definition
                std::string fnString = getTypeName<R>();
                fnString.append(" ").append(name).append("(");
                for (int i = 0; i < fn_traits::nargs; i++) {
                    if (i > 0) fnString.append(", ");
                    fnString.append(types[i]);
                }
                fnString.append(")");

                logging::log("ExposedFunction function string: " + fnString);

                delete[] types;

                tmp->fnString = strdup(fnString.c_str());
                // Push to a vector to be freed when the WebGUI instance is deleted
                pushToVoidPtrVector(wGui, static_cast<void *>(tmp->fnString));
                tmp->f = f;
            }

            *toInit = tmp;
        }

        /**
         * A struct to call C++ functions with a JSON string
         */
        struct Caller {
            /**
             * Call a non-void C++ function
             *
             * @tparam R the function return type
             * @tparam Args the function argument types
             * @param eF the exposed function struct to call
             * @param args the JSON string containing the arguments
             * @param res if this function returns a result
             * @return a result string, to be sent back to js
             */
            template<class R, class...Args>
            static std::string call(ExposedFunction<R(Args...)> *eF, const std::string &args, bool &res) {
                // Convert the JSON string to a string vector (Split it by its arguments)
                std::vector<std::string> argArr = parseJSONInput(args);

                // Call the function and get the result, catch an ArgumentCountDoesNotMatchException
                // if the argument count does not match
                R result;
                try {
                    result = eF->operator()(argArr.size(), argArr.data());
                    res = true;
                } catch (exception::ArgumentCountDoesNotMatchException &) {
                    result = R();
                    res = false;
                } catch (exception::ConversionException &e) {
                    logging::err("ConversionException thrown: " + std::string(e.what()));
                    result = R();
                    res = false;
                }
                std::vector<std::string>().swap(argArr);

                // Return the result as a string
                return TypeConverter<R>::toJsonString(result);
            }

            /**
             * Call a void C++ function
             *
             * @tparam Args the function argument types
             * @param eF the exposed function struct to call
             * @param args the JSON string containing the arguments
             * @param res if this function returns a result
             * @return a empty result string
             */
            template<class...Args>
            static std::string call(ExposedFunction<void(Args...)> *eF, const std::string &args, bool &res) {
                // Convert the JSON string to a string vector (Split it by its arguments)
                std::vector<std::string> argArr = parseJSONInput(args);

                // Call the function
                try {
                    eF->operator()(argArr.size(), argArr.data());
                } catch (exception::ConversionException &e) {
                    logging::err("ConversionException thrown: " + std::string(e.what()));
                }
                std::vector<std::string>().swap(argArr);

                // This function does not return anything
                res = false;
                // Return absolutely nothing
                return "";
            }
        };
    }

    /**
     * Set a general logging function
     *
     * @param loggingFunction the logging function
     */
    CPPJSLIB_EXPORT void setLogger(const std::function<void(const std::string &)> &loggingFunction);

    /**
     * Set a general error function
     *
     * @param errorFunction  the error function
     */
    CPPJSLIB_EXPORT void setError(const std::function<void(const std::string &)> &errorFunction);

    /**
     * The WebGUI class
     */
    class WebGUI {
    public:
        // Delete any constructor not allowed to initialize everything correctly
        // and to prevent heap corruptions to occur

        WebGUI(const WebGUI &) = delete;

        WebGUI &operator=(const WebGUI &) = delete;

#if defined(CPPJSLIB_BUILD_LIB) || !defined (CPPJSLIB_STATIC_DEFINE)

#   ifdef CPPJSLIB_ENABLE_HTTPS

        /**
         * Create a WebGUI instance
         *
         * @param base_dir the base directory
         * @param cert_path the certificate path
         * @param private_key_path the private key path
         * @param websocket_plain_fallback_port a websocket fallback port, if encryption did fail
         */
        CPPJSLIB_EXPORT static WebGUI *create(const std::string &base_dir, const std::string &cert_path,
                                              const std::string &private_key_path,
                                              unsigned short websocket_plain_fallback_port = 0);

#   endif //CPPJSLIB_ENABLE_HTTPS

        /**
         * Create a WebGUI instance
         * It is actually recommended to use WebGUI_ptr
         *
         * @param base_dir the base directory
         */
        CPPJSLIB_EXPORT static WebGUI *create(const std::string &base_dir = "");

        /**
         * Delete the WebGUI
         * It is actually recommended to use WebGUI_ptr
         *
         * @param webGui a pointer to the WebGUI object to deallocate
         */
        CPPJSLIB_EXPORT static void deleteInstance(WebGUI *webGui);

        /**
         * A unique_ptr to handle the deallocation
         */
        using WebGUI_unique = std::unique_ptr<CppJsLib::WebGUI, decltype(&CppJsLib::WebGUI::deleteInstance)>;

        /**
         * A shared_ptr to handle the deallocation
         */
        using WebGUI_shared = std::shared_ptr<CppJsLib::WebGUI>;

        /**
         * Create a WebGUI instance
         *
         * @param base_dir the base directory
         * @return a WebGUI_shared object, which will handle the deallocation
         */
        static inline WebGUI_shared create_shared(const std::string &base_dir = "") {
            return WebGUI_shared(create(base_dir), deleteInstance);
        }

        /**
         * Create a WebGUI instance
         *
         * @param base_dir the base directory
         * @return a WebGUI_unique object, which will handle the deallocation
         */
        static inline WebGUI_unique create_unique(const std::string &base_dir = "") {
            return WebGUI_unique(create(base_dir), deleteInstance);
        }

#   ifdef CPPJSLIB_ENABLE_HTTPS

        /**
         * Create a WebGUI instance
         *
         * @param base_dir the base directory
         * @param cert_path the certificate path
         * @param private_key_path the private key path
         * @param websocket_plain_fallback_port a websocket fallback port, if encryption did fail
         * @return a WebGUI_shared object, which will handle the deallocation
         */
        static inline WebGUI_shared
        create_shared(const std::string &base_dir, const std::string &cert_path, const std::string &private_key_path,
                      unsigned short websocket_plain_fallback_port = 0) {
            return WebGUI_shared(create(base_dir, cert_path, private_key_path, websocket_plain_fallback_port),
                                 deleteInstance);
        }

        /**
         * Create a WebGUI instance
         *
         * @param base_dir the base directory
         * @param cert_path the certificate path
         * @param private_key_path the private key path
         * @param websocket_plain_fallback_port a websocket fallback port, if encryption did fail
         * @return a WebGUI_unique object, which will handle the deallocation
         */
        static inline WebGUI_unique
        create_ptr(const std::string &base_dir, const std::string &cert_path, const std::string &private_key_path,
                   unsigned short websocket_plain_fallback_port = 0) {
            return WebGUI_unique(create(base_dir, cert_path, private_key_path, websocket_plain_fallback_port),
                                 deleteInstance);
        }

#   endif //CPPJSLIB_ENABLE_HTTPS

#else

        /**
         * A unique_ptr to handle the deallocation
         */
        using WebGUI_unique = std::unique_ptr<CppJsLib::WebGUI>;

        /**
         * A shared_ptr to handle the deallocation
         */
        using WebGUI_shared = std::shared_ptr<CppJsLib::WebGUI>;

        /**
         * Create a WebGUI instance
         *
         * @param base_dir the base directory
         * @return a WebGUI_shared object, which will handle the deallocation
         */
        static inline WebGUI_shared create_shared(const std::string &base_dir = "") {
            return std::make_shared<WebGUI>(base_dir);
        }

        /**
         * Create a WebGUI instance
         *
         * @param base_dir the base directory
         * @return a WebGUI_unique object, which will handle the deallocation
         */
        static inline WebGUI_unique create_unique(const std::string &base_dir = "") {
            return std::make_unique<WebGUI>(base_dir);
        }

#   ifdef CPPJSLIB_ENABLE_HTTPS

        /**
         * Create a WebGUI instance
         *
         * @param base_dir the base directory
         * @param cert_path the certificate path
         * @param private_key_path the private key path
         * @param websocket_plain_fallback_port a websocket fallback port, if encryption did fail
         * @return a WebGUI_shared object, which will handle the deallocation
         */
        static inline WebGUI_shared
        create_shared(const std::string &base_dir, const std::string &cert_path, const std::string &private_key_path,
                            unsigned short websocket_plain_fallback_port = 0) {
            return std::make_shared<WebGUI>(base_dir, cert_path, private_key_path, websocket_plain_fallback_port);
        }

        /**
         * Create a WebGUI instance
         *
         * @param base_dir the base directory
         * @param cert_path the certificate path
         * @param private_key_path the private key path
         * @param websocket_plain_fallback_port a websocket fallback port, if encryption did fail
         * @return a WebGUI_unique object, which will handle the deallocation
         */
        static inline WebGUI_unique
        create_ptr(const std::string &base_dir, const std::string &cert_path, const std::string &private_key_path,
                         unsigned short websocket_plain_fallback_port = 0) {
            return std::make_unique<WebGUI>(base_dir, cert_path, private_key_path, websocket_plain_fallback_port);
        }

#   endif //CPPJSLIB_ENABLE_HTTPS

#endif //defined(CPPJSLIB_BUILD_LIB) || !defined (CPPJSLIB_STATIC_DEFINE)

#ifdef CPPJSLIB_STATIC_DEFINE
#   ifdef CPPJSLIB_ENABLE_HTTPS

        /**
         * A WebGUI constructor
         * Defined if a dynamic library is not used
         *
         * @param base_dir the base directory
         * @param cert_path the certificate path
         * @param private_key_path the private key path
         * @param websocket_plain_fallback_port a websocket fallback port, if encryption did fail
         */
        WebGUI(const std::string &base_dir, const std::string &cert_path,
               const std::string &private_key_path, unsigned short websocket_plain_fallback_port = 0);

#   endif //CPPJSLIB_ENABLE_HTTPS

        /**
         * A WebGUI constructor
         * Defined if a dynamic library is not used
         *
         * @param base_dir the base directory
         */
        explicit WebGUI(const std::string &base_dir);

        /**
         * Create a WebGUI instance without a base directory
         * May only be used to start without a http(s) server
         * Defined if a dynamic library is not used
         */
        WebGUI() : WebGUI("") {}

#else

        /**
         * @warning The default constructor will be deleted if a dynamic library is used
         */
        WebGUI() = delete;

#endif //CPPJSLIB_STATIC_DEFINE

#ifdef CPPJSLIB_BUILD_JNI_DLL
        /**
         * @warning Do not use this. This function is just required for the jni lib
         */
        void exportJavaFunction(const std::string& name, const std::string& returnType, std::string *argTypes, int numArgs,
                                const std::function<std::string(std::vector<std::string>)> &fn);
#endif //CPPJSLIB_BUILD_JNI_DLL

        /**
         * @warning Do not use this. Use the export macro instead
         */
        template<class...Args>
        inline void _exportFunction(void(*f)(Args...), std::string name) {
            this->log("Exposing void function with name " + name);
            if (running) {
                this->err("Cannot expose function " + name + " since the web server is already running");
                return;
            }

            util::ExposedFunction<void(Args...)> *exposedF = nullptr;
            util::initExposedFunction(&exposedF, f, name, this);

            if (exposedF) {
                this->pushToVoidPtrVector(static_cast<void *>(exposedF));

                this->insertToInitMap(strdup(name.c_str()), strdup(exposedF->toString().c_str()));
                std::string r = "/callfunc_";
                r.append(name);

                callFromPost(r.c_str(), [exposedF, this, name](std::string req_body, bool &res) {
                    log("Calling C++ function: " + name);
                    return util::Caller::call(exposedF, req_body, res);
                });
            } else {
                this->err("Cannot expose function " + name + ": Unable to allocate memory");
            }
        }

        /**
         * @warning Do not use this. Use the export macro instead
         */
        template<class R, class...Args>
        inline void _exportFunction(R(*f)(Args...), std::string name) {
            this->log("Exposing function with name " + name);
            if (running) {
                this->err("Cannot expose function " + name + " since the web server is already running");
                return;
            }
            util::ExposedFunction<R(Args...)> *exposedF;
            util::initExposedFunction(&exposedF, f, name, this);

            if (exposedF) {
                this->pushToVoidPtrVector(static_cast<void *>(exposedF));

                this->insertToInitMap(strdup(name.c_str()), strdup(exposedF->toString().c_str()));
                std::string r = "/callfunc_";
                r.append(name);

                callFromPost(r.c_str(), [exposedF, this, name](std::string req_body, bool &res) {
                    log("Calling C++ function: " + name);
                    return util::Caller::call(exposedF, req_body, res);
                });
            } else {
                this->err("Cannot expose function " + name + ": Unable to allocate memory");
            }
        }

        /**
         * @warning Do not use this. Use the import macro instead
         */
        template<class...Args>
        inline void _importJsFunction(std::function<void(Args...)> &function, std::string fName) {
            if (fName[0] == '*') {
                fName.erase(0, 1); // Delete first character as it is a *
            }

            this->log("Importing js function with name " + fName);
            util::JsFunction<void(Args...)> *f = nullptr;
            util::initJsFunction(&f, fName, this);

            if (f != nullptr) {
                auto *a = static_cast<void *>(f);
                this->pushToVoidPtrVector(a);
                function = [f, this, fName](Args...args) {
                    log("Calling js function: " + fName);
                    f->operator()(args...);
                };
            } else {
                this->err("Could not import function " + fName + ": Unable to allocate memory");
            }
        }

        /**
         * @warning Do not use this
         */
        CPPJSLIB_EXPORT void
        call_jsFn(std::vector<std::string> *argV, const char *funcName,
                  std::vector<std::string> *results = nullptr, int wait = -1);

#ifdef CPPJSLIB_ENABLE_WEBSOCKET

        /**
         * @warning Do not use this. Use the import macro instead
         */
        template<class R, class...Args>
        inline void
        _importJsFunction(std::function<std::vector<R>(Args...)> &function, std::string fName, int waitS = -1) {
            if (fName[0] == '&') {
                fName.erase(0, 1); // Delete first character as it is a &
            }

            this->log("Importing js function with name " + fName);
            util::JsFunction<std::vector<R>(Args...)> *f = nullptr;
            util::initJsFunction(&f, fName, this, waitS);

            if (f != nullptr) {
                this->pushToVoidPtrVector(static_cast<void *>(f));
                function = [f, this, fName](Args...args) {
                    log("Calling js function: " + fName);
                    return f->operator()(args...);
                };
            } else {
                err("Could not import function " + fName + ": Unable to allocate memory");
            }
        }

        /**
         * Start the web server
         *
         * @param port the port to use
         * @param websocketPort the websocket port to use
         * @param host the hostname to use
         * @param block if this is a blocking call
         * @note this call will sleep for 2-3 seconds, to see if all servers started successfully
         * @return if the operation was successful
         */
        CPPJSLIB_EXPORT bool
        start(int port, int websocketPort, const std::string &host = "localhost", bool block = true);

        /**
         * Start only the websocket servers without the http(s) server
         *
         * @param port the port to listen on
         * @param block if this is a blocking call
         * @note this call will sleep for 1-2 seconds, to see if all servers started successfully
         * @return if the operation was successful
         */
        CPPJSLIB_EXPORT bool startNoWeb(int port, bool block = true);

        /**
         * @warning Do not call this. Websocket support is enabled, therefore a port for the websocket server must be specified
         */
        CPPJSLIB_EXPORT bool start(int port, const std::string &host = "localhost", bool block = true);

#else

        /**
         * Start the web server
         *
         * @param port the port to use
         * @param host the hostname to use
         * @param block if this is a blocking call
         * @note this call will sleep for 1 second, to see if all servers started successfully
         * @return if the operation was successful
         */
        CPPJSLIB_EXPORT bool start(int port, const std::string &host = "localhost", bool block = true);

        /**
         * @warning Do not use this. Use the import macro instead
         */
        template<class R, class...Args>
        inline void
        _importJsFunction(std::function<std::vector<R>(Args...)> &function, std::string fName, int waitS = -1) {
            err("Cannot import non-void javascript function when built without websocket support");
            function = [this] (Args... args) {
                err("Javascript non-void function called but CppJsLib was built without websocket support");
                return std::vector<R>();
            };
        }

#endif //CPPJSLIB_ENABLE_WEBSOCKET

        /**
         * Set the logger
         *
         * @param loggingFunction the logging function
         */
        CPPJSLIB_EXPORT void setLogger(const std::function<void(const std::string &)> &loggingFunction);

        /**
         * Set the error function
         *
         * @param errorFunction the error function
         */
        CPPJSLIB_EXPORT void setError(const std::function<void(const std::string &)> &errorFunction);

        /**
         * Do not use this
         */
        CPPJSLIB_EXPORT void pushToVoidPtrVector(void *f);

        /**
         * Do not use this
         */
        CPPJSLIB_EXPORT void pushToStrVecVector(std::vector<std::string> *v);

        /**
         * Set a mount point
         *
         * @param mnt the mount point
         * @param dir the directory to mount
         */
        CPPJSLIB_EXPORT void set_mount_point(const char *mnt, const char *dir);

        /**
         * Remove a mount point
         *
         * @param mnt the mount point to remove
         */
        CPPJSLIB_EXPORT void remove_mount_point(const char *mnt);

        /**
         * Stop the web server
         *
         * @return if the operation was successful
         */
        CPPJSLIB_EXPORT bool stop();

        /**
         * A function used by the getHttpServer macro
         *
         * @warning Do not use this function. Use the getHttpServer() macro instead
         * @tparam T the param to convert the server pointer to, MUST be httplib::Server* or httplib::SSLServer*
         * @return a pointer to the http Server of this instance
         */
        template<typename T>
        inline std::shared_ptr<T> _getHttpServer() {
            return std::static_pointer_cast<T>(server);
        }

#ifdef CPPJSLIB_ENABLE_WEBSOCKET

        /**
         * Set a function to be called if a client connects to the websocket server
         *
         * @param handler the function
         */
        CPPJSLIB_EXPORT void setWebSocketOpenHandler(const std::function<void()> &handler);

        /**
         * Set a function to be called if a client disconnects from the websocket server
         *
         * @param handler the function
         */
        CPPJSLIB_EXPORT void setWebSocketCloseHandler(const std::function<void()> &handler);

#   ifdef CPPJSLIB_ENABLE_HTTPS

        /**
         * Get the tls websocket server
         *
         * @warning Do not use this function. Use the getTlsWebServer() macro instead
         * @tparam T the type tot convert to
         * @return a shared_ptr to the server
         */
        template<typename T>
        inline std::shared_ptr<T> _getTLSWebServer() {
            return std::static_pointer_cast<T>(ws_server);
        }

#   endif //CPPJSLIB_ENABLE_HTTPS

        /**
         * Get the websocket server
         *
         * @warning Do not use this function. Use the getWebServer() macro instead
         * @tparam T the type tot convert to
         * @return a shared_ptr to the server
         */
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

#else
        /**
         * @warning Do not use this function
         */
        CPPJSLIB_EXPORT void pushToSseVec(const std::string& s);
#endif //CPPJSLIB_ENABLE_WEBSOCKET

// Delete default destructor if the dll is used to prevent heap corruption
#ifndef CPPJSLIB_STATIC_DEFINE

        /**
         * The default destructor is deleted if a dynamic library is used
         */
        ~WebGUI() = delete;

#else

        /**
         * Check if the main server is running
         *
         * @return if the main server is running
         */
        CPPJSLIB_EXPORT bool isRunning();

        /**
         * Check if WebGUI was started without a web server
         *
         * @return if only the websocket servers are started
         */
        CPPJSLIB_EXPORT CPPJSLIB_NODISCARD bool isWebsocketOnly() const;

        ~WebGUI();

#endif //CPPJSLIB_STATIC_DEFINE

        /**
         * Set this to false to not check if any ports are in use when started
         */
        bool check_ports;
        bool running;
        bool stopped;
        using PostHandler = std::function<std::string(std::string req_body, bool &res)>;
#ifdef CPPJSLIB_ENABLE_HTTPS
        const bool ssl;
        const unsigned short fallback_plain;
#endif //CPPJSLIB_ENABLE_HTTPS
    private:
        bool websocket_only;
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
        std::shared_ptr<void> ws_server;
        std::shared_ptr<void> ws_connections;
#   ifdef CPPJSLIB_ENABLE_HTTPS
        std::shared_ptr<void> ws_plain_server;
        std::shared_ptr<void> ws_plain_connections;
#   endif //CPPJSLIB_ENABLE_HTTPS
#endif //CPPJSLIB_ENABLE_WEBSOCKET
        std::shared_ptr<void> server;
        std::vector<std::string> sseVec;
        std::map<std::string, void *> sseEventMap;

        std::map<char *, char *> initMap;
        std::vector<void *> voidPtrVector;
        std::vector<std::vector<std::string> *> strVecVector;

        std::map<std::string, PostHandler> websocketTargets;
        std::map<std::string, std::vector<std::string> *> jsFnCallbacks;
        std::function<void(const std::string &)> _loggingF;
        std::function<void(const std::string &)> _errorF;

        CPPJSLIB_EXPORT void callFromPost(const char *target, const PostHandler &handler);

        CPPJSLIB_EXPORT void log(const std::string &msg);

        CPPJSLIB_EXPORT void err(const std::string &msg);

        CPPJSLIB_EXPORT void insertToInitMap(char *name, char *exposedFStr);
    };

    /**
     * Check if there was an error
     *
     * @return false, if there was an error
     */
    CPPJSLIB_EXPORT CPPJSLIB_MAYBE_UNUSED bool ok();

    /**
     * Get the last error
     *
     * @return the last error string
     */
    CPPJSLIB_EXPORT CPPJSLIB_MAYBE_UNUSED std::string getLastError();

    /**
     * Reset the last error
     */
    CPPJSLIB_EXPORT CPPJSLIB_MAYBE_UNUSED void resetLastError();
}

#endif //CPPJSLIB_WEBGUI_HPP
