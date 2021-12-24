/*
 * CppJsLib.hpp
 *
 * Licensed under the MIT License
 *
 * Copyright (c) 2020 MarkusJx
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * The full license including third-party licenses is available at https://github.com/MarkusJx/CppJsLib/blob/master/LICENSE
 */
#ifndef MARKUSJX_CPPJSLIB_HPP
#define MARKUSJX_CPPJSLIB_HPP

#if __cplusplus >= 201603L || (defined(_MSVC_LANG) && _MSVC_LANG >= 201603L)
#   define CPPJSLIB_UNUSED [[maybe_unused]]
#   define CPPJSLIB_NODISCARD [[nodiscard]]
#else
#   define CPPJSLIB_UNUSED
#   define CPPJSLIB_NODISCARD
#endif

#ifdef CPPJSLIB_ENABLE_HTTPS
#   define CPPHTTPLIB_OPENSSL_SUPPORT
#endif//CPPJSLIB_ENABLE_HTTPS

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)
#   define CPPJSLIB_WINDOWS
#   undef CPPJSLIB_UNIX
#elif defined(__LINUX__) || defined(__APPLE__) || defined (__CYGWIN__) || defined(__linux__) || defined(__FreeBSD__) || \
        defined(unix) || defined(__unix) || defined(__unix__)
#   define CPPJSLIB_UNIX
#   undef CPPJSLIB_WINDOWS
#endif

#define CPPJSLIB_LOG(msg) log("[CppJsLib.hpp:" + std::to_string(__LINE__) + "] [INFO] " + msg)
#define CPPJSLIB_ERR(msg) err("[CppJsLib.hpp:" + std::to_string(__LINE__) + "] [ERROR] " + msg)
#define CPPJSLIB_WARN(msg) err("[CppJsLib.hpp:" + std::to_string(__LINE__) + "] [WARN] " + msg)

#include <functional>
#include <httplib.h>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <type_traits>
#include <future>
#include <utility>
#include <memory>

#ifdef __has_include
#   if __has_include(<nlohmann/json.hpp>)

#       include <nlohmann/json.hpp>

#   elif __has_include(<json.hpp>)
#       include <json.hpp>
#   else
#       error "json.hpp was not found"
#   endif
#else
#   ifdef CPPJSLIB_INCLUDE_NLOHMANN_JSON
#       include <nlohmann/json.hpp>
#   else
#       include <json.hpp>
#   endif //CPPJSLIB_INCLUDE_NLOHMANN_JSON
#endif //__has_include

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
// Define _GNU_SOURCE when compiling with gcc for boost::stacktrace
#   if defined(__GNUG__) && !defined(_GNU_SOURCE)
#       define _GNU_SOURCE
#   endif //__GNUG__

#   include <set>
#   include <websocketpp/server.hpp>
#   include <websocketpp/client.hpp>
#   include <boost/stacktrace.hpp>

#   ifdef CPPJSLIB_ENABLE_HTTPS

#       include <websocketpp/config/asio.hpp>
#       include <websocketpp/config/asio_client.hpp>

#   else

#       include <websocketpp/config/asio_no_tls.hpp>
#       include <websocketpp/config/asio_no_tls_client.hpp>

#   endif//CPPJSLIB_ENABLE_HTTPS
#endif//CPPJSLIB_ENABLE_WEBSOCKET

#ifdef CPPJSLIB_WINDOWS
#   ifdef _MSC_VER
#       pragma comment (lib, "Ws2_32.lib")
#   endif // _MSC_VER

#   include <winsock2.h>
#   include <ws2tcpip.h>
#   include <string>

#elif defined(CPPJSLIB_UNIX)

#   include <unistd.h>
#   include <sys/socket.h>
#   include <netinet/in.h>
#   include <arpa/inet.h>

#endif //CPPJSLIB_WINDOWS

#define expose(func) exportFunction(func, #func)
#define import(func, ...) importFunction(func, #func, ##__VA_ARGS__)

namespace markusjx::cppJsLib {
    const char localhost[10] = "localhost";

    namespace exceptions {
        class CppJsLibException : public std::exception {
        public:
            explicit CppJsLibException(std::string msg) : std::exception(), exceptionType("CppJsLibException"),
                                                          message(std::move(msg)) {
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
                stacktrace = boost::stacktrace::stacktrace();
#endif //CPPJSLIB_ENABLE_WEBSOCKET
            }

            CPPJSLIB_NODISCARD const char *getExceptionType() const noexcept {
                return exceptionType;
            }

            CPPJSLIB_NODISCARD const char *what() const noexcept override {
                return message.c_str();
            }

#ifdef CPPJSLIB_ENABLE_WEBSOCKET

            CPPJSLIB_NODISCARD boost::stacktrace::stacktrace getStacktrace() const {
                return stacktrace;
            }

#endif //CPPJSLIB_ENABLE_WEBSOCKET

        protected:
            CppJsLibException(const char *exceptionType, std::string msg)
                    : std::exception(), exceptionType(exceptionType), message(std::move(msg)) {
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
                stacktrace = boost::stacktrace::stacktrace();
#endif //CPPJSLIB_ENABLE_WEBSOCKET
            }

        private:
            const char *exceptionType;
            const std::string message;
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
            boost::stacktrace::stacktrace stacktrace;
#endif //CPPJSLIB_ENABLE_WEBSOCKET
        };

        class ArgumentCountMismatchException : public CppJsLibException {
        public:
            explicit ArgumentCountMismatchException(const std::string &msg)
                    : CppJsLibException("ArgumentCountMismatchException", msg) {}
        };

        class InvalidArgumentsException : public CppJsLibException {
        public:
            explicit InvalidArgumentsException(const std::string &msg)
                    : CppJsLibException("InvalidArgumentsException", msg) {}
        };
    }// namespace exceptions

    /**
     * A utility namespace
     */
    namespace util {
        /**
         * Check if a port is in use
         *
         * @param addr the host address
         * @param port the port to check
         * @param err the error code reference
         * @return true, if the port is already in use
         */
        inline bool port_is_in_use(const char *addr, unsigned short port, int &err) {
#ifdef CPPJSLIB_WINDOWS
            WSADATA wsaData;
            auto ConnectSocket = INVALID_SOCKET;
            struct addrinfo *result = nullptr, *ptr, hints{};

            // Initialize Winsock
            err = WSAStartup(MAKEWORD(2, 2), &wsaData);
            if (err != 0) {
                return false;
            }

            ZeroMemory(&hints, sizeof(hints));
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;

            // Resolve the server address and port
            err = getaddrinfo(addr, std::to_string(port).c_str(), &hints, &result);
            if (err != 0) {
                WSACleanup();
                return false;
            }

            // Attempt to connect to an address until one succeeds
            for (ptr = result; ptr != nullptr; ptr = ptr->ai_next) {
                // Create a SOCKET for connecting to server
                ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype,
                                       ptr->ai_protocol);
                if (ConnectSocket == INVALID_SOCKET) {
                    err = WSAGetLastError();
                    WSACleanup();
                    return false;
                }

                // Connect to server.
                err = connect(ConnectSocket, ptr->ai_addr, (int) ptr->ai_addrlen);
                if (err == SOCKET_ERROR) {
                    closesocket(ConnectSocket);
                    ConnectSocket = INVALID_SOCKET;
                    continue;
                }
                break;
            }

            freeaddrinfo(result);
            err = 0;

            if (ConnectSocket == INVALID_SOCKET) {
                WSACleanup();
                return false;
            }

            // shutdown the connection since no more data will be sent
            err = shutdown(ConnectSocket, SD_SEND);
            if (err == SOCKET_ERROR) {
                err = WSAGetLastError();
                closesocket(ConnectSocket);
                WSACleanup();
                return false;
            }

            // cleanup
            closesocket(ConnectSocket);
            WSACleanup();

            return true;
#else
            int sock;
            struct sockaddr_in serv_addr{};
            if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
                err = -1;
                return false;
            }

            serv_addr.sin_family = AF_INET;
            serv_addr.sin_port = htons(port);

            // Convert IPv4 and IPv6 addresses from text to binary form
            if (inet_pton(AF_INET, addr, &serv_addr.sin_addr) <= 0) {
                err = -1;
                return false;
            }

            err = connect(sock, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
            if (err < 0) {
                err = 0;
                return false;
            }

            close(sock);
            return true;
#endif //CPPJSLIB_WINDOWS
        }

        /**
         * Generate a random string
         * Source: https://stackoverflow.com/a/440240
         *
         * @param len the length of the string to generate
         * @return the random string
         */
        inline std::string gen_random(const int len) {
            std::string tmp;
            tmp.resize(len);
            static const char alphanum[] =
                    "0123456789"
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    "abcdefghijklmnopqrstuvwxyz";

            // Seed with a real random value, if available
            std::random_device r;

            std::default_random_engine e1(r());
            std::uniform_int_distribution<int> uniform_dist(0, sizeof(alphanum) - 2);

            for (int i = 0; i < len; ++i) {
                tmp[i] = alphanum[uniform_dist(e1)];
            }

            tmp[len] = 0;

            return tmp;
        }

        /**
         * EventDispatcher class
         * Source: https://github.com/yhirose/cpp-httplib/blob/master/example/sse.cc
         */
        class EventDispatcher {
        public:
            /**
             * Create a event dispatcher instance
             */
            EventDispatcher() : clients(0), id_(0), cid_(-1) {}

            /**
             * Wait for an event
             *
             * @param sink the data sink we are listening on
             */
            void wait_event(httplib::DataSink *sink) {
                std::unique_lock<std::mutex> lk(m_);
                int id = id_;
                cv_.wait(lk, [&] { return cid_ == id; });
                if (sink->is_writable()) {
                    sink->write(message_.data(), message_.size());
                } else {
                    clients--;
                }
            }

            /**
             * Send an event message
             *
             * @param message the message to send
             */
            void send_event(const std::string &message) {
                std::lock_guard<std::mutex> lk(m_);
                cid_ = id_++;
                std::stringstream ss;
                ss << "data: " << message << "\n\n";
                message_ = ss.str();
                cv_.notify_all();
            }

            /**
             * The number of clients listening to this event
             */
            std::atomic_int clients;
        private:
            std::mutex m_;
            std::condition_variable cv_;
            std::atomic_int id_;
            std::atomic_int cid_;
            std::string message_;
        };

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
#   ifdef CPPJSLIB_ENABLE_HTTPS
        namespace wspp {
            typedef websocketpp::server<websocketpp::config::asio> server;
            typedef websocketpp::server<websocketpp::config::asio_tls> server_tls;
            typedef websocketpp::lib::shared_ptr<websocketpp::lib::asio::ssl::context> context_ptr;
            typedef websocketpp::client<websocketpp::config::asio_client> client;
            typedef websocketpp::client<websocketpp::config::asio_tls_client> client_tls;
        }// namespace wspp
#   endif//CPPJSLIB_ENABLE_HTTPS

        namespace wspp {
            typedef std::set<websocketpp::connection_hdl,
                    std::owner_less<websocketpp::connection_hdl>>
                    con_list;
            typedef websocketpp::config::asio_client::message_type::ptr message_ptr;
            typedef websocketpp::server<websocketpp::config::asio> server;
            typedef websocketpp::client<websocketpp::config::asio_client> client;
        }

        //using websocketpp::lib::bind;
#endif
    }// namespace util

    /**
     * A response value
     *
     * @tparam T the value type
     */
    template<class T>
    class ResponseValue {
    public:
        /**
         * Create a response value with a value
         *
         * @param val the value
         */
        explicit ResponseValue(const T &val) : value(std::make_shared<T>(val)), exception(nullptr) {}

        /**
         * Create a response value with an exception
         *
         * @param e_ptr the exception pointer
         */
        explicit ResponseValue(std::exception_ptr e_ptr) : value(nullptr), exception(std::move(e_ptr)) {}

        /**
         * Get the stored value.
         * Throws an exception if the response value was created with an exception.
         *
         * @return the stored value
         */
        CPPJSLIB_NODISCARD T get() const {
            if (exception) {
                std::rethrow_exception(exception);
            } else {
                return *value;
            }
        }

        /**
         * Get the stored value.
         * Throws an exception if the response value was created with an exception.
         *
         * @return the stored value
         */
        CPPJSLIB_NODISCARD operator T() const {
            return this->get();
        }

    private:
        std::shared_ptr<T> value;
        std::exception_ptr exception;
    };

    /**
     * A vector type to store responses
     */
    template<class T>
    using responseVector = std::vector<ResponseValue<T>>;

    /**
     * A response for js function calls
     *
     * @tparam T the response type
     */
    template<class T>
    class Response {
    public:
        /**
         * Create a response
         */
        explicit Response() : _data(std::make_shared<responseVector<T>>()), mtx(std::make_shared<std::mutex>()),
                              cv_mtx(std::make_shared<std::mutex>()),
                              cv(std::make_shared<std::condition_variable>()),
                              finished(std::make_shared<std::atomic_bool>(false)) {}

        /**
         * Push a value to the response values
         *
         * @param val the value to push
         */
        void push_back(const T &val) const {
            std::unique_lock<std::mutex> lock(*mtx);
            _data->push_back(ResponseValue<T>(val));
        }

        /**
         * Push an exception pointer to the response values
         *
         * @param e_ptr the exception pointer to push
         */
        void push_back(const std::exception_ptr &e_ptr) const {
            std::unique_lock<std::mutex> lock(*mtx);
            _data->push_back(ResponseValue<T>(e_ptr));
        }

        /**
         * Get a value at an index
         *
         * @param i the index
         * @return the value at i
         */
        CPPJSLIB_NODISCARD ResponseValue<T> at(const size_t i) const {
            std::unique_lock<std::mutex> lock(*mtx);
            return _data->at(i);
        }

        /**
         * Get a value at an index
         *
         * @param i the index
         * @return the value at i
         */
        CPPJSLIB_NODISCARD ResponseValue<T> operator[](const size_t i) const {
            return this->at(i);
        }

        CPPJSLIB_NODISCARD typename responseVector<T>::const_iterator begin() const {
            return _data->begin();
        }

        CPPJSLIB_NODISCARD typename responseVector<T>::const_iterator end() const {
            return _data->end();
        }

        /**
         * Get the response values
         *
         * @return a current copy of the data
         */
        CPPJSLIB_NODISCARD responseVector<T> data() const {
            std::unique_lock<std::mutex> lock(*mtx);
            return responseVector<T>(*_data);
        }

        /**
         * Get the current number of values stored
         *
         * @return the number of values stored
         */
        CPPJSLIB_NODISCARD size_t size() const {
            std::unique_lock<std::mutex> lock(*mtx);
            return _data->size();
        }

        /**
         * Check if there are values stored
         *
         * @return true, if the value vector is not empty
         */
        CPPJSLIB_NODISCARD CPPJSLIB_UNUSED bool has_data() const {
            std::unique_lock<std::mutex> lock(*mtx);
            return !_data->empty();
        }

        /**
         * Wait for all responses to be received
         */
        inline void wait() const {
            std::unique_lock<std::mutex> lock(*cv_mtx);
            cv->wait(lock, [this] {
                return finished->operator bool();
            });

            lock.unlock();
            cv->notify_all();
        }

        /**
         * Wait for all responses to be received or a timeout to be reached
         *
         * @param time the maximum amount of time to wait
         * @return the status
         */
        template<class R, class Period>
        CPPJSLIB_UNUSED CPPJSLIB_NODISCARD std::cv_status wait_for(const std::chrono::duration<R, Period> &time) const {
            std::unique_lock<std::mutex> lock(*cv_mtx);
            return cv->wait_for(lock, time, [this] {
                return finished->operator bool();
            });
        }

        /**
         * Mark all responses received
         */
        void resolve() const {
            if (!finished->operator bool()) {
                finished->exchange(true);
                cv->notify_all();
            }
        }

    private:
        std::shared_ptr<responseVector<T>> _data;
        std::shared_ptr<std::mutex> mtx;
        std::shared_ptr<std::mutex> cv_mtx;
        std::shared_ptr<std::condition_variable> cv;
        std::shared_ptr<std::atomic_bool> finished;
    };

    class connectionBase {
    protected:
        using PostHandler = std::function<nlohmann::json(nlohmann::json req_body)>;

        /**
         * Call a function from a json input
         *
         * @tparam S the number of expected arguments
         * @tparam R the function return type
         * @tparam Args the function arguments
         * @param j the json input
         * @param fn the function to be called
         * @return the function return value
         */
        template<std::size_t... S, class R, class... Args>
        static nlohmann::json
        callFuncFromJsonInput(std::index_sequence<S...>, const nlohmann::json &j, const std::function<R(Args...)> &fn) {
            if constexpr (std::is_same_v<R, void>) {
                fn(j[S].get<typename std::decay_t<Args>>()...);
                return nlohmann::json(nullptr);
            } else {
                R res = fn(j[S].get<typename std::decay_t<Args>>()...);
                nlohmann::json json(res);

                return json;
            }
        }

        /**
         * Call a function from a json input
         *
         * @tparam S the number of expected arguments
         * @tparam R the function return type
         * @tparam Args the function arguments
         * @param j the json input
         * @param fn the function to be called
         * @return the function return value
         */
        template<std::size_t... S, class R, class... Args>
        CPPJSLIB_UNUSED static nlohmann::json
        callFuncFromJsonInput(std::index_sequence<S...>, const nlohmann::json &j, R(*fn)(Args...)) {
            if constexpr (std::is_same_v<R, void>) {
                fn(j[S].get<typename std::decay_t<Args>>()...);
                return nlohmann::json(nullptr);
            } else {
                R res = fn(j[S].get<typename std::decay_t<Args>>()...);
                nlohmann::json json(res);

                return json;
            }
        }

        /**
         * Convert variadic arguments to json
         *
         * @tparam Args the argument types
         * @param args the arguments
         * @return json array
         */
        template<class...Args>
        static nlohmann::json argsToJson(Args...args) {
            nlohmann::json json;
            if constexpr (sizeof...(Args) > 0) {
                CPPJSLIB_UNUSED volatile auto x = {(json.push_back(args), 0)...};
            }

            return json;
        };

        /**
         * A callback function
         */
        class callback_function {
        public:
            /**
             * Initialize the callback_function
             *
             * @param expectsMultiple whether this expects multiple values
             * @param callback the callback for values
             * @param err_callback the callback for exceptions
             * @param res the function to check whether this should be resolved
             */
            callback_function(std::function<void(nlohmann::json)> callback,
                              std::function<void(std::exception_ptr)> err_callback,
                              std::function<bool()> res = nullptr) : expectsMultiple(res),
                                                                     callback(std::move(callback)),
                                                                     error_callback(std::move(err_callback)),
                                                                     resolve(std::move(res)) {}

            const bool expectsMultiple;
            const std::function<void(nlohmann::json)> callback;
            const std::function<void(std::exception_ptr)> error_callback;
            const std::function<bool()> resolve;
        };
    };

    class Client : protected connectionBase {
    public:
        // Set the websocket types
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
        using websocket_type = util::wspp::client;
#else
        using websocket_type = void;
#endif//CPPJSLIB_ENABLE_WEBSOCKET

        Client() {
            log = [](const std::string &) {};
            err = log;
        }

        /**
         * Set the logging function
         *
         * @param fn the logging function
         */
        void setLogger(std::function<void(std::string)> fn) {
            log = std::move(fn);
        }

        /**
         * Set the error logging function
         *
         * @param fn the logging function
         */
        void setError(std::function<void(std::string)> fn) {
            err = std::move(fn);
        }

        /**
         * Expose a function to js
         *
         * @note Use the expose macro instead of this
         * @tparam R the function return type
         * @tparam Args the function arguments
         * @param func the function to export
         * @param name the function name
         */
        template<class R, class... Args>
        void exportFunction(const std::function<R(Args...)> &func, const std::string &name) {
            exposedFunctions.insert(
                    std::pair<std::string, PostHandler>(name, [&func, this](const nlohmann::json &json) {
                        if (json.size() != sizeof...(Args)) {
                            std::stringstream ss;
                            ss << "The number of arguments did not match: " << json.size();
                            ss << " vs. " << sizeof...(Args);
                            throw exceptions::ArgumentCountMismatchException(ss.str());
                        }

                        auto sequence = std::index_sequence_for<Args...>{};
                        return callFuncFromJsonInput(sequence, json, func);
                    }));
        }

        /**
         * Expose a function to js
         *
         * @note Use the expose macro instead of this
         * @tparam R the function return type
         * @tparam Args the function arguments
         * @param func the function to expose
         * @param name the function name
         */
        template<class R, class... Args>
        void exportFunction(R (&func)(Args...), const std::string &name) {
            exposedFunctions.insert(
                    std::pair<std::string, PostHandler>(name, [&func, this](const nlohmann::json &json) {
                        if (json.size() != sizeof...(Args)) {
                            std::stringstream ss;
                            ss << "The number of arguments did not match: " << json.size();
                            ss << " vs. " << sizeof...(Args);
                            throw exceptions::ArgumentCountMismatchException(ss.str());
                        }

                        auto sequence = std::index_sequence_for<Args...>{};
                        return callFuncFromJsonInput(sequence, json, &func);
                    }));
        }

        /**
         * Import a function from js
         *
         * @note Use the import(1) macro instead
         * @tparam R the function return type
         * @tparam Args the function arguments
         * @param func the function to import
         * @param name the function name
         */
        template<class R, class...Args>
        void importFunction(std::function<R(Args...)> &func, const std::string &name) {
            func = [this, name](Args...args) {
                if (!this->running()) {
                    throw exceptions::CppJsLibException("No server is running");
                }

                // Convert the arguments to json
                nlohmann::json json = argsToJson(args...);

                // Create a json promise
                std::promise<nlohmann::json> promise;
                std::future<nlohmann::json> future = promise.get_future();

                // Call the function
                callFunction(json, name, callback_function([&promise](const nlohmann::json &data) {
                    promise.set_value(data);
                }, [&promise](const std::exception_ptr &ptr) {
                    promise.set_exception(ptr);
                }));

                // Wait for the promise to be resolved
                future.wait();

                // Return the return value, if not void
                if constexpr (std::is_same_v<R, void>) {
                    future.get();
                } else {
                    R res = future.get().get<R>();
                    return res;
                }
            };
        }

        /**
         * Import a function from js with a promise
         *
         * @note Use the import(1) macro instead
         * @tparam R the function return type
         * @tparam Args the function arguments
         * @param func the function to import
         * @param name the function name
         */
        template<class R, class...Args>
        void importFunction(std::function<void(std::promise<R> &, Args...)> &func, const std::string &name) {
            std::function < R(Args...) > imported;
            this->importFunction(imported, name);

            func = [imported](std::promise<R> &promise, Args...args) {
                // Wait for the function to be resolved in a different thread
                std::thread([&imported, &promise, args...] {
                    try {
                        // If the promise has no return type, don't expect one
                        if constexpr (std::is_same_v<R, void>) {
                            imported(args...);
                            promise.set_value();
                        } else {
                            R res = imported(args...);
                            promise.set_value(res);
                        }
                    } catch (...) {
                        try {
                            promise.set_exception(std::current_exception());
                        } catch (...) {}
                    }
                }).detach();
            };
        };

        void connect(const std::string &scheme_host_port, bool block = true) {
            if (running()) {
                throw exceptions::CppJsLibException("The client is already connected");
            }

            http_client = std::make_shared<httplib::Client>(scheme_host_port.c_str());
            httplib::Result res = http_client->Get("/init_ws");
            if (res && res->status == 200) {
                CPPJSLIB_LOG("Initializing with message: " + res->body);
                wsInitializer initializer(res->body);
                if (initializer.ws) {
                    http_client->stop();
                    http_client.reset();
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
                    if (!startWebsocket(initializer.host, initializer.port, block, initializer.tls)) {
                        client.reset();
                        throw exceptions::CppJsLibException("Could not connect to the websocket server");
                    }
#else
                    throw exceptions::CppJsLibException("The server has websocket support, this client does "
                                                        "not have websocket support");
#endif //CPPJSLIB_ENABLE_WEBSOCKET
                } else {
                    http_client->Get("/cppjslib_events", [this](const char *data, size_t size) {
                        std::string toSend = handleMessage(std::string(data, size));
                        if (!toSend.empty()) {
                            http_client->Post("/cppjslib", toSend, "application/json");
                        }
                        return true;
                    });

                    if (block) {
                        while (running()) {
                            std::this_thread::sleep_for(std::chrono::milliseconds(100));
                        }
                    }
                }
            } else if (!res) {
                http_client->stop();
                http_client.reset();

                std::string error;
                switch (res.error()) {
                    case httplib::Error::Success:
                        error = "success";
                        break;
                    case httplib::Error::Unknown:
                        error = "unknown";
                        break;
                    case httplib::Error::Connection:
                        error = "connection";
                        break;
                    case httplib::Error::BindIPAddress:
                        error = "bindIpAddress";
                        break;
                    case httplib::Error::Read:
                        error = "read";
                        break;
                    case httplib::Error::Write:
                        error = "write";
                        break;
                    case httplib::Error::ExceedRedirectCount:
                        error = "exceedRedirectCount";
                        break;
                    case httplib::Error::Canceled:
                        error = "Canceled";
                        break;
                    case httplib::Error::SSLConnection:
                        error = "sslConnection";
                        break;
                    case httplib::Error::SSLLoadingCerts:
                        error = "sslLoadingCerts";
                        break;
                    case httplib::Error::SSLServerVerification:
                        error = "sslServerVerification";
                        break;
                    case httplib::Error::UnsupportedMultipartBoundaryChars:
                        error = "unsupportedMultipartBoundaryChars";
                        break;
                    case httplib::Error::Compression:
                        error = "compression";
                        break;
                    default:
                        error = "unknown";
                }

                throw exceptions::CppJsLibException("The connection finished with error code: " + error);
            } else {
                http_client->stop();
                http_client.reset();
                throw exceptions::CppJsLibException("The server returned status: " + std::to_string(res->status));
            }
        }

#ifdef CPPJSLIB_ENABLE_WEBSOCKET

        bool connectWebsocketOnly(const std::string &hostname, uint16_t port, bool block = true) {
            if (running()) {
                throw exceptions::CppJsLibException("The client is already connected");
            }

            return startWebsocket(hostname, port, block, false);
        }

#endif //CPPJSLIB_ENABLE_WEBSOCKET

        virtual bool running() {
            std::unique_lock<std::mutex> lock(connect_mtx);
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
            return client && !client->stopped() || http_client && http_client->is_valid();
#else
            return http_client && http_client->is_valid();
#endif //CPPJSLIB_ENABLE_WEBSOCKET
        }

        virtual void stop() {
            if (running()) {
                std::unique_lock<std::mutex> lock(connect_mtx);
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
                if (client && !client->stopped()) client->stop();
                if (run_thread) {
                    run_thread->join();
                    run_thread.reset();
                }
                client.reset();
#endif //CPPJSLIB_ENABLE_WEBSOCKET
                if (http_client) http_client->stop();
                http_client.reset();
            }
        }

        ~Client() {
            std::unique_lock<std::mutex> lock(connect_mtx);
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
            if (client && !client->stopped()) {
                client->stop();
                if (run_thread) {
                    run_thread->join();
                    run_thread.reset();
                }
                client.reset();
            }
#endif //CPPJSLIB_ENABLE_WEBSOCKET
            if (http_client) http_client->stop();
            http_client.reset();
        }

    protected:
        class wsInitializer {
        public:
            explicit wsInitializer(const std::string &msg) {
                nlohmann::json json = nlohmann::json::parse(msg);
                ws = json["ws"];
                if (ws) {
                    host = json["host"];
                    port = json["port"];
                    tls = json["tls"];
                } else {
                    port = 0;
                    tls = false;
                }
            }

            bool ws;
            std::string host;
            uint16_t port;
            bool tls;
        };

        std::string handleMessage(const std::string &msg) {
            CPPJSLIB_LOG("Parsing message: " + msg);
            try {
                nlohmann::json json = nlohmann::json::parse(msg);

                if (json["header"] == "callback") {
                    if (callbacks.find(json["header"]) != callbacks.end()) {
                        if (json["ok"]) {
                            callbacks.at(json["header"]).callback(json["data"]);
                        } else {
                            callbacks.at(json["header"]).error_callback(
                                    std::make_exception_ptr(exceptions::CppJsLibException(json["data"])));
                        }
                    } else {
                        CPPJSLIB_ERR("Received data with callback, but this callback does not exist");
                    }
                } else if (json["header"] == "call") {
                    nlohmann::json result;
                    result["header"] = "callback";
                    result["callback"] = json["callback"];
                    if (exposedFunctions.find(json["func"]) == exposedFunctions.end()) {
                        result["ok"] = false;
                        result["data"] = "The function with name " + json["func"].dump() + " is not exported";
                        return result.dump();
                    }

                    try {
                        result["data"] = exposedFunctions[json["func"]](json["data"]);
                        result["ok"] = true;
                    } catch (const std::exception &e) {
                        result["ok"] = false;
                        result["data"] = e.what();
                    }
                    return result.dump();
                }
            } catch (const std::exception &e) {
                CPPJSLIB_ERR(e.what());
            } catch (...) {
                CPPJSLIB_ERR("An unknown error occurred");
            }

            return std::string();
        }

#ifdef CPPJSLIB_ENABLE_WEBSOCKET

        virtual bool startWebsocket(const std::string &hostname, uint16_t port, bool block, bool tls) {
            if (tls) {
                throw exceptions::CppJsLibException("Cannot connect to the websocket server in tls mode");
            }

            std::unique_lock<std::mutex> lock(connect_mtx);
            client = std::make_shared<websocket_type>();

            std::string uri = "ws://" + hostname + ":" + std::to_string(port);
            CPPJSLIB_LOG("Connecting to websocket on: " + uri);
            try {
                // Initialize ASIO
                client->init_asio();

                // Register our message handler
                client->set_message_handler(
                        [this](const websocketpp::connection_hdl &hdl, const util::wspp::client::message_ptr &msg) {
                            try {
                                std::string res = handleMessage(msg->get_payload());
                                if (!res.empty()) {
                                    CPPJSLIB_LOG("Sending message: " + res);
                                    client->send(hdl, res, websocketpp::frame::opcode::text);
                                }
                            } catch (const std::exception &e) {
                                CPPJSLIB_ERR(e.what());
                            }
                        });

                websocketpp::lib::error_code ec;
                connection = client->get_connection(uri, ec);
                if (ec) {
                    CPPJSLIB_ERR("Could not create connection: " + ec.message());
                    return false;
                }

                // Note that connect here only requests a connection. No network messages are
                // exchanged until the event loop starts running in the next line.
                client->connect(connection);

                // Start the ASIO io_service run loop
                // this will cause a single connection to be made to the server. c.run()
                // will exit when this connection is closed.
                if (block) {
                    lock.unlock();
                    client->run();
                    CPPJSLIB_LOG("Websocket connection closed");
                    return false;
                } else {
                    run_thread = std::make_unique<std::thread>([this] {
                        try {
                            client->run();
                            CPPJSLIB_LOG("Websocket connection closed");
                        } catch (const std::exception &e) {
                            CPPJSLIB_ERR("Exception thrown: " + e.what());
                        }
                    });
                    return true;
                }
            } catch (websocketpp::exception const &e) {
                CPPJSLIB_ERR(e.what());
                return false;
            }
        }

#endif //CPPJSLIB_ENABLE_WEBSOCKET

        /**
         * Call a function
         *
         * @param args the function argument json array
         * @param funcName the function name
         * @param promise the promise to be resolved when the call finished
         */
        virtual void callFunction(const nlohmann::json &args, const std::string &funcName,
                                  const callback_function &callback_func) {
            // Dump the list of arguments into a json string
            nlohmann::json j;
            j["header"] = "call";
            j["func"] = funcName;
            j["data"] = args;

            // Generate a callback id
            std::string callback = util::gen_random(40);
            {
                std::unique_lock<std::mutex> lock(callbacksMutex);
                while (callbacks.count(callback) != 0) {
                    callback = util::gen_random(40);
                }
            }
            CPPJSLIB_LOG("Waiting for results from javascript");

            j["callback"] = callback;
            std::string str = j.dump();

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
            if (!client) {
                CPPJSLIB_LOG("Calling js function via server sent events: " + str);

                try {
                    http_client->Post("/cppjslib", str, "application/json");
                } catch (...) {
                    CPPJSLIB_ERR("Could not call the function via server sent events");
                    return;
                }
            } else {
                CPPJSLIB_LOG("Calling js function via websocket: " + str);

                // Send request to all clients
                CPPJSLIB_LOG("Sending request");
                try {
                    connection->send(str, websocketpp::frame::opcode::value::text);
                } catch (...) {
                    CPPJSLIB_ERR("Could not send message");
                    return;
                }
            }
#else
            CPPJSLIB_LOG("Calling js function via server sent events: " + str);

            try {
                http_client->Post("/cppjslib", str, "application/json");
            } catch (std::exception &) {
                CPPJSLIB_ERR("Could not call the function via server sent events");
                return;
            }
#endif //CPPJSLIB_ENABLE_WEBSOCKET
            {
                std::unique_lock<std::mutex> lock(callbacksMutex);
                callbacks.insert(std::pair<std::string, callback_function>(callback, callback_func));
            }
        }

        std::unique_ptr<std::thread> run_thread;
        std::function<void(std::string)> log, err;
        std::mutex connect_mtx;
        std::shared_ptr<httplib::Client> http_client;

        // The callback functions. Used for when the js functions return values.
        // Has a random string as a key, used to identify the callback
        // and a reference to a promise to be resolved.
        std::map<std::string, callback_function> callbacks;
        std::mutex callbacksMutex;
    private:
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
        websocket_type::connection_ptr connection;
#endif //CPPJSLIB_ENABLE_WEBSOCKET
        std::shared_ptr<websocket_type> client;
        std::map<std::string, PostHandler> exposedFunctions;
    };

#ifdef CPPJSLIB_ENABLE_HTTPS

    class CPPJSLIB_UNUSED SSLClient : public Client {
    public:
        // Set the websocket types
#   ifdef CPPJSLIB_ENABLE_WEBSOCKET
        using websocket_ssl_type = util::wspp::client_tls;
#   else
        using websocket_ssl_type = void;
#   endif//CPPJSLIB_ENABLE_WEBSOCKET

        explicit SSLClient(std::string cert_verify_file)
                : Client(), cert_verify_file(std::move(cert_verify_file)) {}

        bool running() override {
            std::unique_lock<std::mutex> lock(connect_mtx);
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
            return client_ssl && !client_ssl->stopped() || http_client && http_client->is_valid();
#else
            return http_client && http_client->is_valid();
#endif //CPPJSLIB_ENABLE_WEBSOCKET
        }

        void stop() override {
            if (running()) {
                std::unique_lock<std::mutex> lock(connect_mtx);
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
                client_ssl->stop();
                if (run_thread) {
                    run_thread->join();
                    run_thread.reset();
                }
#endif //CPPJSLIB_ENABLE_WEBSOCKET
                if (http_client) http_client->stop();
                http_client.reset();
            }
        }

        ~SSLClient() {
            std::unique_lock<std::mutex> lock(connect_mtx);
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
            if (client_ssl && !client_ssl->stopped()) {
                client_ssl->stop();
                if (run_thread) {
                    run_thread->join();
                    run_thread.reset();
                }
            }
#endif //CPPJSLIB_ENABLE_WEBSOCKET
            if (http_client) http_client->stop();
            http_client.reset();
        }

    private:
#ifdef CPPJSLIB_ENABLE_WEBSOCKET

        bool startWebsocket(const std::string &hostname, uint16_t port, bool block, bool tls) override {
            std::unique_lock<std::mutex> lock(connect_mtx);
            client_ssl = std::make_shared<websocket_ssl_type>();
            std::string uri = (tls ? "wss://" : "ws://") + hostname + ":" + std::to_string(port);

            try {
                // Set logging to be pretty verbose (everything except message payloads)
                //c.set_access_channels(websocketpp::log::alevel::all);
                //c.clear_access_channels(websocketpp::log::alevel::frame_payload);
                //c.set_error_channels(websocketpp::log::elevel::all);

                // Initialize ASIO
                client_ssl->init_asio();

                // Register our message handler
                client_ssl->set_message_handler(
                        [this](const websocketpp::connection_hdl &hdl, const util::wspp::client_tls::message_ptr &msg) {
                            try {
                                std::string res = handleMessage(msg->get_payload());
                                if (!res.empty()) {
                                    client_ssl->send(hdl, res, websocketpp::frame::opcode::text);
                                }
                            } catch (const std::exception &e) {
                                CPPJSLIB_ERR(e.what());
                            }
                        });
                client_ssl->set_tls_init_handler([this, hostname](const websocketpp::connection_hdl &) {
                    return on_tls_init(hostname.c_str());
                });

                websocketpp::lib::error_code ec;
                connection = client_ssl->get_connection(uri, ec);
                if (ec) {
                    CPPJSLIB_ERR("Could not create connection: " + ec.message());
                    return false;
                }

                // Note that connect here only requests a connection. No network messages are
                // exchanged until the event loop starts running in the next line.
                client_ssl->connect(connection);

                //c.get_alog().write(websocketpp::log::alevel::app, "Connecting to " + uri);

                // Start the ASIO io_service run loop
                // this will cause a single connection to be made to the server. c.run()
                // will exit when this connection is closed.
                if (block) {
                    lock.unlock();
                    client_ssl->run();
                    return false;
                } else {
                    run_thread = std::make_unique<std::thread>([this] {
                        client_ssl->run();
                    });
                    return true;
                }
            } catch (websocketpp::exception const &e) {
                CPPJSLIB_ERR(e.what());
                return false;
            }
        }

#endif //CPPJSLIB_ENABLE_WEBSOCKET

        /**
         * Call a function
         *
         * @param args the function argument json array
         * @param funcName the function name
         * @param promise the promise to be resolved when the call finished
         */
        void callFunction(const nlohmann::json &args, const std::string &funcName,
                          const callback_function &callback_func) override {
            // Dump the list of arguments into a json string
            nlohmann::json j;
            j["header"] = "call";
            j["func"] = funcName;
            j["data"] = args;

            // Generate a callback id
            std::string callback = util::gen_random(40);
            {
                std::unique_lock<std::mutex> lock(callbacksMutex);
                while (callbacks.count(callback) != 0) {
                    callback = util::gen_random(40);
                }
            }
            CPPJSLIB_LOG("Waiting for results from javascript");

            j["callback"] = callback;
            std::string str = j.dump();

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
            if (!client_ssl) {
                CPPJSLIB_LOG("Calling js function via server sent events: " + str);

                try {
                    http_client->Post("/cppjslib", str, "application/json");
                } catch (...) {
                    CPPJSLIB_ERR("Could not call the function via server sent events");
                    return;
                }
            } else {
                CPPJSLIB_LOG("Calling js function via websocket: " + str);

                // Send request to all clients
                CPPJSLIB_LOG("Sending request");
                try {
                    connection->send(str, websocketpp::frame::opcode::value::text);
                } catch (...) {
                    CPPJSLIB_ERR("Could not send message");
                    return;
                }
            }
#else
            CPPJSLIB_LOG("Calling js function via server sent events: " + str);

            try {
                http_client->Post("/cppjslib", str, "application/json");
            } catch (std::exception &) {
                CPPJSLIB_ERR("Could not call the function via server sent events");
                return;
            }
#endif //CPPJSLIB_ENABLE_WEBSOCKET
            {
                std::unique_lock<std::mutex> lock(callbacksMutex);
                callbacks.insert(std::pair<std::string, callback_function>(callback, callback_func));
            }
        }

#ifdef CPPJSLIB_ENABLE_WEBSOCKET

        // Verify that one of the subject alternative names matches the given hostname
        static bool verify_subject_alternative_name(const char *hostname, X509 *cert) {
            STACK_OF(GENERAL_NAME) *san_names = nullptr;

            san_names = (STACK_OF(GENERAL_NAME) *) X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr);
            if (san_names == nullptr) {
                return false;
            }

            int san_names_count = sk_GENERAL_NAME_num(san_names);

            bool result = false;

            for (int i = 0; i < san_names_count; i++) {
                const GENERAL_NAME *current_name = sk_GENERAL_NAME_value(san_names, i);

                if (current_name->type != GEN_DNS) {
                    continue;
                }

                char const *dns_name = (char const *) ASN1_STRING_get0_data(current_name->d.dNSName);

                // Make sure there isn't an embedded NUL character in the DNS name
                if (ASN1_STRING_length(current_name->d.dNSName) != strlen(dns_name)) {
                    break;
                }
                // Compare expected hostname with the CN
                result = (strcasecmp(hostname, dns_name) == 0);
            }
            sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);

            return result;
        }

        // Verify that the certificate common name matches the given hostname
        static bool verify_common_name(char const *hostname, X509 *cert) {
            // Find the position of the CN field in the Subject field of the certificate
            int common_name_loc = X509_NAME_get_index_by_NID(X509_get_subject_name(cert), NID_commonName, -1);
            if (common_name_loc < 0) {
                return false;
            }

            // Extract the CN field
            X509_NAME_ENTRY *common_name_entry = X509_NAME_get_entry(X509_get_subject_name(cert), common_name_loc);
            if (common_name_entry == nullptr) {
                return false;
            }

            // Convert the CN field to a C string
            ASN1_STRING *common_name_asn1 = X509_NAME_ENTRY_get_data(common_name_entry);
            if (common_name_asn1 == nullptr) {
                return false;
            }

            char const *common_name_str = (char const *) ASN1_STRING_get0_data(common_name_asn1);

            // Make sure there isn't an embedded NUL character in the CN
            if (ASN1_STRING_length(common_name_asn1) != strlen(common_name_str)) {
                return false;
            }

            // Compare expected hostname with the CN
            return (strcasecmp(hostname, common_name_str) == 0);
        }

        /**
         * This code is derived from examples and documentation found ato00po
         * http://www.boost.org/doc/libs/1_61_0/doc/html/boost_asio/example/cpp03/ssl/client.cpp
         * and
         * https://github.com/iSECPartners/ssl-conservatory
         */
        static bool verify_certificate(const char *hostname, bool preverified, boost::asio::ssl::verify_context &ctx) {
            // The verify callback can be used to check whether the certificate that is
            // being presented is valid for the peer. For example, RFC 2818 describes
            // the steps involved in doing this for HTTPS. Consult the OpenSSL
            // documentation for more details. Note that the callback is called once
            // for each certificate in the certificate chain, starting from the root
            // certificate authority.

            // Retrieve the depth of the current cert in the chain. 0 indicates the
            // actual server cert, upon which we will perform extra validation
            // (specifically, ensuring that the hostname matches. For other certs we
            // will use the 'preverified' flag from Asio, which incorporates a number of
            // non-implementation specific OpenSSL checking, such as the formatting of
            // certs and the trusted status based on the CA certs we imported earlier.
            int depth = X509_STORE_CTX_get_error_depth(ctx.native_handle());

            // if we are on the final cert and everything else checks out, ensure that
            // the hostname is present on the list of SANs or the common name (CN).
            if (depth == 0 && preverified) {
                X509 *cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());

                if (verify_subject_alternative_name(hostname, cert) || verify_common_name(hostname, cert)) {
                    return true;
                } else {
                    return false;
                }
            }

            return preverified;
        }

        util::wspp::context_ptr on_tls_init(const char *hostname) {
            util::wspp::context_ptr ctx = websocketpp::lib::make_shared<boost::asio::ssl::context>(
                    boost::asio::ssl::context::sslv23);

            try {
                ctx->set_options(boost::asio::ssl::context::default_workarounds |
                                 boost::asio::ssl::context::no_sslv2 |
                                 boost::asio::ssl::context::no_sslv3 |
                                 boost::asio::ssl::context::single_dh_use);


                ctx->set_verify_mode(boost::asio::ssl::verify_peer);
                ctx->set_verify_callback([hostname](bool preverified, boost::asio::ssl::verify_context &ctx) {
                    return verify_certificate(hostname, preverified, ctx);
                });

                // Here we load the CA certificates of all CA's that this client trusts.
                ctx->load_verify_file(cert_verify_file);
            } catch (const std::exception &e) {
                CPPJSLIB_ERR(e.what());
            }
            return ctx;
        }

        websocket_ssl_type::connection_ptr connection;
#endif //CPPJSLIB_ENABLE_WEBSOCKET

        std::string cert_verify_file;
        std::shared_ptr<websocket_ssl_type> client_ssl;
    };

#endif//CPPJSLIB_ENABLE_HTTPS

/**
 * The main CppJsLib server
 */
    class Server : protected connectionBase {
    public:
        // Set the websocket types
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
        using websocket_con_list = util::wspp::con_list;
        using websocket_type = util::wspp::server;
#else
        using websocket_con_list = void;
        using websocket_type = void;
#endif//CPPJSLIB_ENABLE_WEBSOCKET

        /**
         * Initialize the server
         *
         * @param base_dir the base directory
         */
        explicit Server(std::string base_dir = ".") : check_ports(true), _running(false),
                                                      base_dir(std::move(base_dir)), javascriptCallbacks(),
                                                      callbacksMutex(), websocketConnectionsMutex(),
                                                      websocketTargets(), initString(), initMap() {
            // Create the web server
            webServer = std::make_shared<httplib::Server>();
            webServer->set_mount_point("/", this->base_dir.c_str());

            // Set the message handler
            webServer->Post("/cppjslib", [this](const httplib::Request &req, httplib::Response &res) {
                try {
                    std::string toSend = this->handleMessages(req.body);
                    if (!toSend.empty()) {
                        res.set_content(toSend, "application/json");
                    }
                    res.status = 200;
                } catch (const std::exception &e) {
                    CPPJSLIB_ERR(e.what());
                    res.status = 500;
                } catch (...) {
                    CPPJSLIB_ERR("An unknown error occurred");
                    res.status = 500;
                }
            });

            // Create the event dispatcher
            eventDispatcher = std::make_shared<util::EventDispatcher>();

            websocket_only = false;
            no_websocket = false;

            log = [](const std::string &) {};
            err = log;

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
            CPPJSLIB_LOG("Initializing websocket server");
            websocketServer = std::make_shared<util::wspp::server>();
            websocketConnections = std::make_shared<util::wspp::con_list>();

            initWebsocketServer(websocketServer, websocketConnections, websocketConnectionsMutex);
#endif //CPPJSLIB_ENABLE_WEBSOCKET
        }

        /**
         * Copying this doesn't make any sense, don't do it
         */
        Server(const Server &) = delete;

        /**
         * Copying this doesn't make any sense, don't do it
         */
        Server &operator=(const Server &) = delete;

#ifdef CPPJSLIB_ENABLE_WEBSOCKET

        /**
         * Start without the web server (websocket only)
         *
         * @param port the websocket port to listen on
         * @param host the host address
         * @param block whether to block after starting the server
         * @return true, if the server could be started
         */
        bool startNoWeb(uint16_t port, const std::string &host = "localhost", bool block = true) {
            if (check_ports) {
                int error = 0;
                if (util::port_is_in_use(host.c_str(), port, error)) {
                    CPPJSLIB_ERR("port " + std::to_string(port) + " is already in use");
                    return false;
                } else if (error != 0) {
                    CPPJSLIB_ERR("port_is_in_use finished with code " + std::to_string(error));
                }
            }

            websocket_only = true;
            no_websocket = false;

            return startWebsocketServers(host, port, block);
        }

#endif //CPPJSLIB_ENABLE_WEBSOCKET

        /**
         * Start the server without the websocket server
         *
         * @param port the port to listen on
         * @param host the host address
         * @param block whether to block
         * @return whether the servers could be started
         */
        bool startNoWebSocket(uint16_t port, const std::string &host = localhost, bool block = true) {
            CPPJSLIB_LOG("Starting without websocket server");

            if (port == 0) {
                throw exceptions::CppJsLibException("Cannot start servers with the port 0");
            }

            if (port == 80) {
                std::cerr << "[WARN] Starting the http server without the websocket server on port 80 will cause js "
                             "functions not to be called. To avoid this, switch to a different port or enable the "
                             "websocket server." << std::endl;
                CPPJSLIB_WARN("Starting the http server without the websocket server on port 80 will cause js "
                              "functions not to be called. To avoid this, switch to a different port or enable the "
                              "websocket server.");
            }

            // Check if this is started or websocket-only
            if (websocket_only) {
                throw exceptions::CppJsLibException("The Server is already started in websocket-only mode");
            }

            if (_running) {
                throw exceptions::CppJsLibException("The Server is already running");
            }

            no_websocket = true;
            websocket_only = false;

            // Check if the ports are occupied, if enabled
            if (check_ports) {
                int _err = 0;
                if (util::port_is_in_use(host.c_str(), port, _err)) {
                    CPPJSLIB_ERR("port " + std::to_string(port) + " is already in use");
                    return false;
                } else if (_err != 0) {
                    CPPJSLIB_ERR("port_is_in_use finished with code " + std::to_string(_err));
                }
            }

            CPPJSLIB_LOG("Starting web server");
            nlohmann::json init_ws_json;
            init_ws_json["ws"] = false;
            addInitHandlers(init_ws_json.dump());

            // Start SSE listeners
            // Source: https://github.com/yhirose/cpp-httplib/blob/master/example/sse.cc
            addSseListener();

            _running = true;
            startWebServer(port, host, block);

            return _running;
        }

        /**
         * Start the servers
         *
         * @param port the port of the web server to listen on. If set to 0, it will not be started
         * @param host the host address
         * @param websocketPort the websocket port. If set to 0, the server will not be started
         * @param block whether to block
         * @return true, if the servers could be started
         */
        bool start(uint16_t port, const std::string &host = localhost, uint16_t websocketPort = 0, bool block = true) {
            if (websocket_only) {
                throw exceptions::CppJsLibException("The Server is already started in websocket-only mode");
            }

            if (_running) {
                throw exceptions::CppJsLibException("The Server is already running");
            }

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
            // If the port is zero, don't start the web server
            if (port == 0) {
                return startNoWeb(websocketPort, host, block);
            }

            // If the port is zero, don't start the websocket server
            if (websocketPort == 0) {
                return startNoWebSocket(port, host, block);
            }

            // If the ports should be checked, check them
            if (check_ports) {
                int wsErr = 0;
                if (util::port_is_in_use(host.c_str(), websocketPort, wsErr)) {
                    CPPJSLIB_ERR("port " + std::to_string(websocketPort) + " is already in use");
                    return false;
                } else if (wsErr != 0) {
                    CPPJSLIB_ERR("port_is_in_use finished with code " + std::to_string(wsErr));
                }
            }
#else
            if (port == 0) {
                throw exceptions::CppJsLibException("Cannot start with port number 0");
            }
#endif //CPPJSLIB_ENABLE_WEBSOCKET

            // Check if the ports are occupied, if enabled
            if (check_ports) {
                int _err = 0;
                if (util::port_is_in_use(host.c_str(), port, _err)) {
                    CPPJSLIB_ERR("port " + std::to_string(port) + " is already in use");
                    return false;
                } else if (_err != 0) {
                    CPPJSLIB_ERR("port_is_in_use finished with code " + std::to_string(_err));
                }
            }

            CPPJSLIB_LOG("Starting web server");
            nlohmann::json init_ws_json;
            generate_init_array(init_ws_json, host, websocketPort);

            // Add the init handlers
            addInitHandlers(init_ws_json.dump());

            // Start SSE listeners
            // Source: https://github.com/yhirose/cpp-httplib/blob/master/example/sse.cc
#ifndef CPPJSLIB_ENABLE_WEBSOCKET
            addSseListener();
#endif //CPPJSLIB_ENABLE_WEBSOCKET

            _running = true;

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
            bool wsRunning;
            wsRunning = startWebsocketServers(host, websocketPort, false);
#else
            bool wsRunning = true;
#endif //CPPJSLIB_ENABLE_WEBSOCKET

            startWebServer(port, host, block);

            return _running && wsRunning;
        }

        /**
         * Start the servers.
         * If a port number is set to zero, this server will not be started
         *
         * @param promise the promise to be resolved
         * @param port the port to listen on
         * @param host the host address
         * @param websocketPort the websocket port
         * @param block whether to block. If set to true, the promise will
         *              only be resolved when the servers are stopped or an error occurs
         */
        void start(std::promise<bool> &promise, uint16_t port, const std::string &host = localhost,
                   uint16_t websocketPort = 0, bool block = true) {
            std::thread([this, &promise, port, host, websocketPort, block] {
                try {
                    bool res = this->start(port, host, websocketPort, block);
                    promise.set_value(res);
                } catch (...) {
                    try {
                        promise.set_exception(std::current_exception());
                    } catch (...) {}
                }
            }).detach();
        }

        /**
         * Expose a function to js
         *
         * @note Use the expose macro instead of this
         * @tparam R the function return type
         * @tparam Args the function arguments
         * @param func the function to export
         * @param name the function name
         */
        template<class R, class... Args>
        void exportFunction(const std::function<R(Args...)> &func, const std::string &name) {
            initMap.insert(std::pair<std::string, size_t>(name, sizeof...(Args)));
            callFuncFromJs(name, [&func, this](const nlohmann::json &json) {
                if (json.size() != sizeof...(Args)) {
                    std::stringstream ss;
                    ss << "The number of arguments did not match: " << json.size();
                    ss << " vs. " << sizeof...(Args);
                    throw exceptions::ArgumentCountMismatchException(ss.str());
                }

                auto sequence = std::index_sequence_for<Args...>{};
                return callFuncFromJsonInput(sequence, json, func);
            });
        }

        /**
         * Expose a function to js
         *
         * @note Use the expose macro instead of this
         * @tparam R the function return type
         * @tparam Args the function arguments
         * @param func the function to expose
         * @param name the function name
         */
        template<class R, class... Args>
        void exportFunction(R (&func)(Args...), const std::string &name) {
            initMap.insert(std::pair<std::string, size_t>(name, sizeof...(Args)));
            callFuncFromJs(name, [&func, this](const nlohmann::json &json) {
                if (json.size() != sizeof...(Args)) {
                    std::stringstream ss;
                    ss << "The number of arguments did not match: " << json.size();
                    ss << " vs. " << sizeof...(Args);
                    throw exceptions::ArgumentCountMismatchException(ss.str());
                }

                auto sequence = std::index_sequence_for<Args...>{};
                return callFuncFromJsonInput(sequence, json, &func);
            });
        }

        /**
         * Import a function from js
         *
         * @note Use the import(1) macro instead
         * @tparam R the function return type
         * @tparam Args the function arguments
         * @param func the function to import
         * @param name the function name
         * @param expect_result whether to expect a result. Only works if R = void. Defaults to true
         */
        template<class R, class...Args>
        void importFunction(std::function<R(Args...)> &func, const std::string &name, bool expect_result = true) {
            func = [this, name, expect_result](Args...args) {
                if (!this->running()) {
                    throw exceptions::CppJsLibException("No server is running");
                }

                // Check if any client is connected
                if (check_all_callbacks_received(0)) {
                    if constexpr (std::is_same_v<R, void>) {
                        if (expect_result) {
                            throw exceptions::CppJsLibException("No client is listening");
                        } else {
                            CPPJSLIB_LOG("Not sending a request as no client is connected");
                            return;
                        }
                    } else {
                        throw exceptions::CppJsLibException("No client is listening");
                    }
                }

                // Convert the arguments to json
                nlohmann::json json = argsToJson(args...);

                if (std::is_same_v<R, void> && !expect_result) {
                    // Call the function
                    // Ignore the callback results, as requested
                    callJavascriptFunction(json, name, callback_function([](const nlohmann::json &) {},
                                                                         [](const std::exception_ptr &) {}));
                } else {
                    // Create a json promise
                    std::promise<nlohmann::json> promise;
                    std::future<nlohmann::json> future = promise.get_future();

                    // Call the function
                    callJavascriptFunction(json, name, callback_function([&promise](const nlohmann::json &data) {
                        promise.set_value(data);
                    }, [&promise](const std::exception_ptr &ptr) {
                        promise.set_exception(ptr);
                    }));

                    // Wait for the promise to be resolved
                    future.wait();

                    // Return the return value, if not void
                    if constexpr (std::is_same_v<R, void>) {
                        future.get();
                    } else {
                        R res = future.get().get<R>();
                        return res;
                    }
                }
            };
        }

        /**
         * Import a function from js with a promise
         *
         * @note Use the import(1) macro instead
         * @tparam R the function return type
         * @tparam Args the function arguments
         * @param func the function to import
         * @param name the function name
         */
        template<class R, class...Args>
        void importFunction(std::function<void(std::promise<R> &, Args...)> &func, const std::string &name) {
            std::function < R(Args...) > imported;
            this->importFunction(imported, name);

            func = [imported](std::promise<R> &promise, Args...args) {
                // Wait for the function to be resolved in a different thread
                std::thread([&imported, &promise, args...] {
                    try {
                        // If the promise has no return type, don't expect one
                        if constexpr (std::is_same_v<R, void>) {
                            imported(args...);
                            promise.set_value();
                        } else {
                            R res = imported(args...);
                            promise.set_value(res);
                        }
                    } catch (...) {
                        try {
                            promise.set_exception(std::current_exception());
                        } catch (...) {}
                    }
                }).detach();
            };
        };

        /**
         * Import a function expecting multiple responses
         *
         * @note Use the import(1) macro instead
         * @tparam R the return type
         * @tparam Args the argument types
         * @param func the function to import
         * @param name the function name
         */
        template<class R, class...Args>
        void importFunction(std::function<Response<R>(Args...)> &func, const std::string &name) {
            func = [this, name](Args...args) {
                if (!this->running()) {
                    throw exceptions::CppJsLibException("No server is running");
                }

                if (check_all_callbacks_received(0)) {
                    throw exceptions::CppJsLibException("No client is listening");
                }

                // Convert the arguments to json
                nlohmann::json json = argsToJson(args...);

                Response<R> response;
                callJavascriptFunction(json, name, callback_function([response](const nlohmann::json &data) {
                    response.push_back(data.get<R>());
                }, [response](const std::exception_ptr &ptr) {
                    response.push_back(ptr);
                }, [this, response] {
                    if (check_all_callbacks_received(response.size())) {
                        response.resolve();
                        return true;
                    } else {
                        return false;
                    }
                }));

                return response;
            };
        };

        /**
         * Check if the servers are running
         *
         * @return true, if they are running
         */
        CPPJSLIB_NODISCARD virtual bool running() const {
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
            if (websocket_only) {
                return websocketServer->is_listening();
            } else {
                if (no_websocket) {
                    return websocketServer->is_listening();
                } else {
                    return webServer->is_running();
                }
            }
#else
            return webServer->is_running();
#endif //CPPJSLIB_ENABLE_WEBSOCKET
        }

        /**
         * Stop the servers
         */
        virtual void stop() {
            if (running()) {
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
                if (!websocket_only) {
                    CPPJSLIB_LOG("Stopping the web server");
                    webServer->stop();
                }

                CPPJSLIB_LOG("Closing all websocket connections");
                std::unique_lock lock(websocketConnectionsMutex);
                for (const auto &con : *websocketConnections) {
                    std::error_code ec;
                    websocketServer->close(con, websocketpp::close::status::going_away,
                                           "The server is shutting down", ec);
                    if (ec) {
                        CPPJSLIB_ERR("Could not close a websocket connection: " + ec.message());
                    }
                }
                websocketConnections->clear();

                CPPJSLIB_LOG("Stopping the websocket server");
                try {
                    websocketServer->stop_listening();
                    websocketServer->stop();
                } catch (...) {
                    CPPJSLIB_ERR("Could not close the websocket server(s)");
                }
#else
                webServer->stop();
#endif //CPPJSLIB_ENABLE_WEBSOCKET
            }
        }

        /**
         * Stop the servers with a promise
         *
         * @param promise the promise to be resolved when all servers are stopped
         */
        void stop(std::promise<void> &promise) {
            std::thread([&promise, this] {
                stop();

                while (running()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                }

                promise.set_value();
            }).detach();
        }

        /**
         * Set the logging function
         *
         * @param fn the logging function
         */
        void setLogger(std::function<void(std::string)> fn) {
            log = std::move(fn);
        }

        /**
         * Set the error logging function
         *
         * @param fn the logging function
         */
        void setError(std::function<void(std::string)> fn) {
            err = std::move(fn);
        }

        /**
         * Get the http server
         *
         * @return the http server
         */
        CPPJSLIB_UNUSED CPPJSLIB_NODISCARD std::shared_ptr<httplib::Server> getHttpServer() const {
            return webServer;
        }

        /**
         * Get the websocket server
         *
         * @return the websocket server
         */
        CPPJSLIB_UNUSED CPPJSLIB_NODISCARD std::shared_ptr<websocket_type> getWebsocketServer() const {
            return websocketServer;
        }

        /**
         * Delete the server instance
         */
        ~Server() {
            std::promise<void> promise;
            stop(promise);

            std::future<void> future = promise.get_future();
            future.wait();
        }

        /**
         * Whether to check if ports are already in use
         * when the servers are started
         */
        bool check_ports;
    protected:
        Server(std::string base_dir, bool websocket_only, bool no_websocket) : base_dir(std::move(base_dir)),
                                                                               _running(false),
                                                                               check_ports(true),
                                                                               websocket_only(websocket_only),
                                                                               no_websocket(no_websocket) {}

#ifdef CPPJSLIB_ENABLE_WEBSOCKET

        virtual bool startWebsocketServers(const std::string &host, uint16_t websocketPort, bool block) {
            CPPJSLIB_LOG("Starting websocket server");
            return startNoWeb_f(websocketServer, host, websocketPort, block);
        }

#endif //CPPJSLIB_ENABLE_WEBSOCKET

        virtual bool check_all_callbacks_received(size_t response_size) {
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
            if (!no_websocket) {
                std::unique_lock<std::mutex> lock(websocketConnectionsMutex);
                return response_size == websocketConnections->size();
            } else {
                return response_size == eventDispatcher->clients;
            }
#else
            return response_size == eventDispatcher->clients;
#endif //CPPJSLIB_ENABLE_WEBSOCKET
        }

        virtual void generate_init_array(nlohmann::json &init_ws_json, CPPJSLIB_UNUSED const std::string &host,
                                         CPPJSLIB_UNUSED uint16_t websocketPort) {
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
            init_ws_json["ws"] = true;
            init_ws_json["host"] = host;
            init_ws_json["port"] = websocketPort;
            init_ws_json["tls"] = false;
#else
            init_ws_json["ws"] = false;
#endif //CPPJSLIB_ENABLE_WEBSOCKET
        }

        /**
         * Handle messages from js
         *
         * @param msg the message to parse
         * @return the result
         */
        std::string handleMessages(const std::string &msg) {
            // Parse a message of the format:
            // [HEADER] <[DATA]> <[CALLBACK]> <[OK]> <[FUNCTION_NAME]>
            // The header field may equal the following strings:
            //  "init": Gets all exported functions (websocket_only mode only)
            //      Requires the field 'callback' to be set
            //  "callback": The data is a response to a function call from c++ to js.
            //      Data will contain the js function return value.
            //      Requires 'callback' and 'data' to be set
            //  "ping": Returns "pong"
            //  "call": Call a function
            //      Data will contain the function arguments
            //      Requires the 'func, 'callback' and 'data' fields to be set
            // ========================================================
            // The 'data' field may contain function arguments.
            // The 'callback' field will always contain a random string to identify a response
            // The 'ok' field is set to true, when the function call failed
            // The 'func' field may contain the name of the function to call

            CPPJSLIB_LOG("Parsing message " + msg);

            nlohmann::json json = nlohmann::json::parse(msg);
            if (json.find("header") == json.end()) {
                CPPJSLIB_ERR("json structure did not contain a header");
            }

            std::string header = json["header"];

            if (header == "ping") {
                return "pong";
            } else if (header == "init") {
                if (json.find("callback") == json.end()) {
                    CPPJSLIB_ERR("json structure had no callback");
                    return {};
                }

                nlohmann::json callback;
                callback["callback"] = json["callback"];
                callback["data"] = initString;
                std::string payload = callback.dump();
                log("Sending callback: " + payload);
                return payload;
            } else if (header == "callback") { // This is an answer to a previous function call
                if (json.find("data") == json.end()) {
                    CPPJSLIB_ERR("json structure did not contain data");
                    return {};
                }

                if (json.find("callback") == json.end()) {
                    CPPJSLIB_ERR("json structure had no callback");
                    return {};
                }

                std::unique_lock<std::mutex> lock(callbacksMutex);
                if (javascriptCallbacks.find(json["callback"]) != javascriptCallbacks.end()) {
                    callback_function &callback = javascriptCallbacks.at(json["callback"]);
                    try {
                        // Get the data
                        if (json["ok"]) {
                            callback.callback(json["data"]);
                        } else {
                            try {
                                callback.error_callback(
                                        std::make_exception_ptr(exceptions::CppJsLibException(json["data"])));
                            } catch (...) {}
                        }
                    } catch (const std::exception &e) {
                        CPPJSLIB_ERR(e.what());
                        try {
                            callback.error_callback(std::make_exception_ptr(e));
                        } catch (...) {}
                    }

                    try {
                        if ((callback.expectsMultiple && callback.resolve()) || !callback.expectsMultiple) {
                            javascriptCallbacks.erase(json["callback"]);
                        }
                    } catch (const std::exception &e) {
                        CPPJSLIB_ERR("Could not erase a callback: " + std::string(e.what()));
                    }
                } else {
                    CPPJSLIB_ERR("javascriptCallbacks did not contain the requested callback id");
                }
            } else if (header == "call") {
                if (json.find("callback") == json.end()) {
                    CPPJSLIB_ERR("json structure had no callback");
                    return {};
                }

                nlohmann::json callback;
                callback["callback"] = json["callback"];

                if (json.find("data") == json.end()) {
                    callback["data"] = "json structure did not contain data";
                    callback["ok"] = false;
                    return callback.dump();
                }

                if (json.find("func") == json.end()) {
                    callback["data"] = "The json structure did not contain a function name";
                    callback["ok"] = false;
                    return callback.dump();
                }

                if (websocketTargets.find(json["func"]) != websocketTargets.end()) {
                    CPPJSLIB_LOG("Calling function: " + json["func"].dump());
                    try {
                        callback["data"] = websocketTargets.at(json["func"])(json["data"]);
                        callback["ok"] = true;
                    } catch (const std::exception &e) {
                        err("Exception thrown: " + std::string(e.what()));
                        callback["ok"] = false;
                        callback["data"] = e.what();
                    }

                    return callback.dump();
                } else {
                    callback["data"] = "The function name was not exported";
                    callback["ok"] = false;
                    return callback.dump();
                }
            }

            return {};
        }

#ifdef CPPJSLIB_ENABLE_WEBSOCKET

        /**
         * Init a websocket server
         *
         * @tparam EndpointType the endpoint type
         * @param s the server to initialize
         * @param list the connection list
         */
        template<typename EndpointType>
        void initWebsocketServer(std::shared_ptr<EndpointType> s, const std::shared_ptr<util::wspp::con_list> &list,
                                 std::mutex &mtx) {
            try {
                s->set_open_handler([list, this, &mtx](const websocketpp::connection_hdl &hdl) {
                    try {
                        std::unique_lock<std::mutex> lock(mtx);
                        list->insert(hdl);
                    } catch (...) {
                        CPPJSLIB_ERR("Could not insert the connection");
                    }
                });

                s->set_close_handler([list, this, &mtx](const websocketpp::connection_hdl &hdl) {
                    try {
                        std::unique_lock<std::mutex> lock(mtx);
                        list->erase(hdl);
                    } catch (...) {
                        CPPJSLIB_ERR("Could not erase the connection");
                    }
                });

                s->set_access_channels(websocketpp::log::alevel::all);
                s->clear_access_channels(websocketpp::log::alevel::frame_payload);

                s->init_asio();
            } catch (const std::exception &e) {
                CPPJSLIB_ERR("Could not initialize websocket server. Error: " + std::string(e.what()));
            } catch (...) {
                CPPJSLIB_ERR("An unknown exception occurred");
            }
        }

        /**
         * Start a websocket server
         *
         * @tparam Endpoint the endpoint type
         * @param ws_server whe websocket server pointer
         * @param host the host address
         * @param port the port to listen on
         * @param block whether to block
         * @return whether the server could be started
         */
        template<typename Endpoint>
        bool startNoWeb_f(std::shared_ptr<Endpoint> ws_server, const std::string &host, int port, bool block) {
            ws_server->set_message_handler([ws_server, this](const websocketpp::connection_hdl &hdl,
                                                             const util::wspp::server::message_ptr &msg) {
                onMessage<Endpoint>(ws_server, hdl, msg);
            });

            if (block) {
                CPPJSLIB_LOG("Starting websocket server in blocking mode");
                startWebsocketServer(ws_server, host, port);
            } else {
                CPPJSLIB_LOG("Starting websocket server in non-blocking mode");
                std::thread websocketThread([&ws_server, port, host, this] {
                    startWebsocketServer(ws_server, host, port);
                });
                websocketThread.detach();

                std::this_thread::sleep_for(std::chrono::seconds(1));
            }

            if (ws_server->is_listening()) {
                CPPJSLIB_LOG("Successfully started websocket server");
            } else {
                CPPJSLIB_ERR("Could not start websocket server");
            }

            return ws_server->is_listening();
        }

#endif //CPPJSLIB_ENABLE_WEBSOCKET

        /**
         * Call a javascript function
         *
         * @param args the function argument json array
         * @param funcName the function name
         * @param promise the promise to be resolved when the call finished
         */
        virtual void callJavascriptFunction(const nlohmann::json &args, const std::string &funcName,
                                            const callback_function &callback_func) {
            // Dump the list of arguments into a json string
            nlohmann::json j;
            j["header"] = "call";
            j["func"] = funcName;
            j["data"] = args;

            // Generate a callback id
            std::string callback = util::gen_random(40);
            {
                std::unique_lock<std::mutex> lock(callbacksMutex);
                while (javascriptCallbacks.find(callback) != javascriptCallbacks.end()) {
                    callback = util::gen_random(40);
                }
            }
            CPPJSLIB_LOG("Waiting for results from javascript");

            j["callback"] = callback;
            std::string str = j.dump();

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
            if (no_websocket) {
                CPPJSLIB_LOG("Calling js function via server sent events: " + str);

                try {
                    eventDispatcher->send_event(str);
                } catch (...) {
                    CPPJSLIB_ERR("Could not call the function via server sent events");
                    return;
                }
            } else {
                CPPJSLIB_LOG("Calling js function via websocket: " + str);

                // Send request to all clients
                CPPJSLIB_LOG("Sending request");
                std::unique_lock<std::mutex> lock(websocketConnectionsMutex);
                for (const auto &it : *websocketConnections) {
                    try {
                        websocketServer->send(it, str, websocketpp::frame::opcode::value::text);
                    } catch (...) {
                        CPPJSLIB_ERR("Could not send message");
                        return;
                    }
                }
            }
#else
            CPPJSLIB_LOG("Calling js function via server sent events: " + str);

            try {
                eventDispatcher->send_event(str);
            } catch (std::exception &) {
                CPPJSLIB_ERR("Could not call the function via server sent events");
                return;
            }
#endif //CPPJSLIB_ENABLE_WEBSOCKET
            {
                std::unique_lock<std::mutex> lock(callbacksMutex);
                javascriptCallbacks.insert(std::pair<std::string, callback_function>(callback, callback_func));
            }
        }

        // The logging and error functions
        std::function<void(std::string)> log, err;
        bool websocket_only; // Whether this is websocket only
        bool no_websocket; // Whether websocket is disabled
        std::string base_dir; // The web base directory

        // The javascript callbacks. Used for when the js functions return values.
        // Has a random string as a key, used to identify the callback
        // and a reference to a promise to be resolved.
        std::map<std::string, callback_function> javascriptCallbacks;
        std::mutex callbacksMutex;

        // The http(s) server
        std::shared_ptr<httplib::Server> webServer;

        // The event dispatcher as an alternative to websockets
        std::shared_ptr<util::EventDispatcher> eventDispatcher;

        // The websocket connection list
        std::shared_ptr<websocket_con_list> websocketConnections;
        std::mutex websocketConnectionsMutex;
    private:
        /**
         * Initialize the server sent event listener
         */
        void addSseListener() {
            CPPJSLIB_LOG("Start listening for server sent events");
            webServer->Get("/cppjslib_events", [this](const httplib::Request &, httplib::Response &res) {
                CPPJSLIB_LOG("Client connected to server sent event");
                res.set_chunked_content_provider("text/event-stream", [this](size_t, httplib::DataSink &sink) {
                    eventDispatcher->clients++;
                    eventDispatcher->wait_event(&sink);
                    return true;
                });
            });
        }

        /**
         * Add the init handler
         *
         * @param init_ws_string the websocket initializer string
         */
        void addInitHandlers(const std::string &init_ws_string) {
            nlohmann::json initList;
            for (const auto &p: initMap) {
                initList[p.first] = p.second;
            }
            initMap.clear();

            initString = initList.dump();
            const auto initHandler = [this](const httplib::Request &, httplib::Response &res) {
                res.set_content(initString, "application/json");
            };

            const auto init_ws_handler = [init_ws_string](const httplib::Request &, httplib::Response &res) {
                res.set_content(init_ws_string, "application/json");
            };

            webServer->Get("/init", initHandler);
            webServer->Get("/init_ws", init_ws_handler);
        }

        /**
         * Start the web server
         *
         * @param port the http server port
         * @param host the host address
         * @param block whether to block
         */
        void startWebServer(uint16_t port, const std::string &host, bool block) {
            if (!block) {
                CPPJSLIB_LOG("Starting web server in non-blocking mode");
                std::thread([&host, port, this] {
                    try {
                        if (!webServer->listen(host.c_str(), port)) {
                            CPPJSLIB_ERR("Could not start web server");
                            _running = false;
                        }
                    } catch (...) {
                        CPPJSLIB_ERR("Could not start web server");
                    }
                }).detach();

                // Sleep for one second, so the servers can fail
                CPPJSLIB_LOG("Sleeping for a short while");
                std::this_thread::sleep_for(std::chrono::seconds(1));
            } else {
                CPPJSLIB_LOG("Starting web server in blocking mode");
                if (!webServer->listen(host.c_str(), port)) {
                    CPPJSLIB_ERR("Could not start web server");
                    _running = false;
                }
            }
        }

        /**
         * Add a exported function to the websocketTargets map
         *
         * @param name the function name
         * @param fn the function
         */
        void callFuncFromJs(const std::string &name, const PostHandler &fn) {
            websocketTargets.insert(std::pair<std::string, PostHandler>(name, fn));
        }

#ifdef CPPJSLIB_ENABLE_WEBSOCKET

        /**
         * Start the websocket server
         *
         * @tparam EndpointType the endpoint type
         * @param s the server to initialize
         * @param host the host address
         * @param port the port to listen on
         * @param err the error logger
         * @param log the logging function
         */
        template<typename EndpointType>
        void startWebsocketServer(std::shared_ptr<EndpointType> s, const std::string &host, int port) {
            try {
                CPPJSLIB_LOG("Starting websocket to listen on host " + host + " and port " + std::to_string(port));
                s->listen(host, std::to_string(port));
                s->start_accept();

                s->run();
            } catch (const std::exception &e) {
                CPPJSLIB_ERR("Could not start listening. Error: " + std::string(e.what()));
            } catch (...) {
                CPPJSLIB_ERR("An unknown exception occurred");
            }
        }

        /**
         * The on message listener
         *
         * @tparam Endpoint the endpoint type
         * @param s the server
         * @param err the error logger
         * @param log the logging function
         * @param messageHandler the message handler function
         * @param hdl the connection handle
         * @param msg the received message
         */
        template<typename Endpoint>
        void onMessage(std::shared_ptr<Endpoint> s, const websocketpp::connection_hdl &hdl,
                       const util::wspp::server::message_ptr &msg) {
            try {
                CPPJSLIB_LOG("Received data: " + msg->get_payload());
                std::string toSend = handleMessages(msg->get_payload());
                if (!toSend.empty()) {
                    s->send(hdl, toSend, websocketpp::frame::opcode::text);
                }
            } catch (const std::exception &e) {
                CPPJSLIB_ERR("Websocket receive failed: " + std::string(e.what()));
            }
        }

#endif //CPPJSLIB_ENABLE_WEBSOCKET

        bool _running; // Whether the servers are running or stopped
        std::string initString; // The init string. Contains all exported functions in a json array as a string.

        std::map<std::string, PostHandler> websocketTargets; // The websocket target functions

        // The function initializer map.
        // Contains the function name as a key
        // and the number of arguments as a value.
        std::map<std::string, size_t> initMap;
        std::shared_ptr<websocket_type> websocketServer; // The websocket server
    };

#ifdef CPPJSLIB_ENABLE_HTTPS

    /**
     * A ssl server
     */
    class CPPJSLIB_UNUSED SSLServer : public Server {
    public:
        // Set the websocket types
#   ifdef CPPJSLIB_ENABLE_WEBSOCKET
        using websocket_fallback_type = util::wspp::server;
        using websocket_fallback_connections_type = util::wspp::con_list;
        using websocket_ssl_type = util::wspp::server_tls;
#   else
        using websocket_fallback_type = void;
        using websocket_fallback_connections_type = void;
        using websocket_ssl_type = void;
#   endif//CPPJSLIB_ENABLE_WEBSOCKET

        SSLServer(const std::string &base_dir, const std::string &cert_path, const std::string &private_key_path,
                  uint16_t fallback_plain_port = 0) : Server(base_dir, false, false),
                                                      fallback_plain_port(fallback_plain_port) {
            if (cert_path.empty() || private_key_path.empty()) {
                throw exceptions::InvalidArgumentsException(
                        "The certificate or private key paths were empty");
            }

            webServer = std::make_shared<httplib::SSLServer>(cert_path.c_str(), private_key_path.c_str());
            webServer->set_mount_point("/", this->base_dir.c_str());

            // Set the message handler
            webServer->Post("/cppjslib", [this](const httplib::Request &req, httplib::Response &res) {
                res.set_content(this->handleMessages(req.body), "application/json");
            });

            eventDispatcher = std::make_shared<util::EventDispatcher>();

#   ifdef CPPJSLIB_ENABLE_WEBSOCKET
            setPassword();

            CPPJSLIB_LOG("Initializing tls websocket server");
            websocketConnections = std::make_shared<websocket_con_list>();
            websocketTLSServer = std::make_shared<websocket_ssl_type>();
            initWebsocketTLS(websocketTLSServer, cert_path, private_key_path);
            initWebsocketServer(websocketTLSServer, websocketConnections, websocketConnectionsMutex);

            if (fallback_plain_port) {
                CPPJSLIB_LOG("Initializing websocket plain fallback server");
                websocketFallbackServer = std::make_shared<websocket_fallback_type>();
                websocketFallbackConnections = std::make_shared<websocket_fallback_connections_type>();
                initWebsocketServer(websocketFallbackServer, websocketFallbackConnections, websocketConnectionsMutex);
            }
#   endif//CPPJSLIB_ENABLE_WEBSOCKET
        }

        /**
         * Check if the servers are running
         *
         * @return true, if they are running
         */
        CPPJSLIB_NODISCARD bool running() const override {
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
            if (websocket_only) {
                return websocketTLSServer->is_listening();
            } else {
                if (no_websocket) {
                    return websocketTLSServer->is_listening();
                } else {
                    return webServer->is_running();
                }
            }
#else
            return webServer->is_running();
#endif //CPPJSLIB_ENABLE_WEBSOCKET
        }

        /**
         * Stop the servers
         */
        void stop() override {
            if (running()) {
#   ifdef CPPJSLIB_ENABLE_WEBSOCKET
                if (!websocket_only) {
                    CPPJSLIB_LOG("Stopping the web server");
                    webServer->stop();
                }

                CPPJSLIB_LOG("Disconnecting all websocket tls clients");
                std::unique_lock lock(websocketConnectionsMutex);
                for (const auto &con : *websocketConnections) {
                    std::error_code ec;
                    websocketTLSServer->close(con, websocketpp::close::status::going_away,
                                              "The server is shutting down", ec);
                    if (ec) {
                        CPPJSLIB_ERR("Could not close a websocket connection: " + ec.message());
                    }
                }
                websocketConnections->clear();

                CPPJSLIB_LOG("Stopping the websocket server");
                try {
                    websocketTLSServer->stop_listening();
                    websocketTLSServer->stop();

                    if (fallback_plain_port) {
                        CPPJSLIB_LOG("Disconnecting all websocket clients");
                        for (const auto &con : *websocketFallbackConnections) {
                            std::error_code ec;
                            websocketFallbackServer->close(con, websocketpp::close::status::going_away,
                                                           "The server is shutting down", ec);
                            if (ec) {
                                CPPJSLIB_ERR("Could not close a websocket connection: " + ec.message());
                            }
                        }
                        websocketFallbackConnections->clear();

                        CPPJSLIB_LOG("Stopping the websocket plain fallback server");
                        websocketFallbackServer->stop_listening();
                        websocketFallbackServer->stop();
                    }
                } catch (...) {
                    CPPJSLIB_ERR("Could not close the websocket server(s)");
                }
#   else
                webServer->stop();
#   endif //CPPJSLIB_ENABLE_WEBSOCKET
            }
        }

        /**
         * Get the websocket tls server
         *
         * @return the websocket tls server
         */
        CPPJSLIB_UNUSED CPPJSLIB_NODISCARD std::shared_ptr<websocket_ssl_type> getWebsocketTLSServer() const {
            return websocketTLSServer;
        }

        /**
         * Get the websocket fallback server
         *
         * @return the websocket fallback server
         */
        CPPJSLIB_UNUSED CPPJSLIB_NODISCARD std::shared_ptr<websocket_fallback_type> getWebsocketFallbackServer() const {
            return websocketFallbackServer;
        }

    private:
#   ifdef CPPJSLIB_ENABLE_WEBSOCKET

        bool startWebsocketServers(const std::string &host, uint16_t websocketPort, bool block) override {
            if (fallback_plain_port) {
                CPPJSLIB_LOG("Starting tls websocket server");
                bool wsRunning = startNoWeb_f(websocketTLSServer, host, websocketPort, false);

                CPPJSLIB_LOG("Starting websocket plain fallback server");
                return wsRunning && startNoWeb_f(websocketFallbackServer, host, fallback_plain_port, block);
            } else {
                CPPJSLIB_LOG("Starting tls websocket server");
                return startNoWeb_f(websocketTLSServer, host, websocketPort, block);
            }
        }

#   endif //CPPJSLIB_ENABLE_WEBSOCKET

        bool check_all_callbacks_received(size_t response_size) override {
#   ifdef CPPJSLIB_ENABLE_WEBSOCKET
            if (!no_websocket) {
                return response_size == (websocketConnections->size() + websocketFallbackConnections->size());
            } else {
                return response_size == eventDispatcher->clients;
            }
#   else
            return response_size == eventDispatcher->clients;
#   endif //CPPJSLIB_ENABLE_WEBSOCKET
        }

        void generate_init_array(nlohmann::json &init_ws_json, CPPJSLIB_UNUSED const std::string &host,
                                 CPPJSLIB_UNUSED uint16_t websocketPort) override {
#   ifdef CPPJSLIB_ENABLE_WEBSOCKET
            init_ws_json["ws"] = true;
            init_ws_json["host"] = host;
            init_ws_json["port"] = websocketPort;
            init_ws_json["tls"] = true;
            if (fallback_plain_port) {
                init_ws_json["fallback_plain"] = true;
                init_ws_json["fallback_plain_port"] = fallback_plain_port;
            } else {
                init_ws_json["fallback_plain"] = false;
            }
#   else
            init_ws_json["ws"] = false;
#   endif //CPPJSLIB_ENABLE_WEBSOCKET
        }

        /**
         * Call a javascript function
         *
         * @param args the function argument json array
         * @param funcName the function name
         * @param promise the promise to be resolved when the call finished
         */
        void callJavascriptFunction(const nlohmann::json &args, const std::string &funcName,
                                    const callback_function &callback_func) override {
            // Dump the list of arguments into a json string
            nlohmann::json j;
            j["header"] = "call";
            j["func"] = funcName;
            j["data"] = args;

            // Generate a callback id
            std::string callback = util::gen_random(40);
            {
                std::unique_lock<std::mutex> lock(callbacksMutex);
                while (javascriptCallbacks.count(callback) != 0) {
                    callback = util::gen_random(40);
                }
            }
            CPPJSLIB_LOG("Waiting for results from javascript");

            j["callback"] = callback;
            std::string str = j.dump();

#   ifdef CPPJSLIB_ENABLE_WEBSOCKET
            if (no_websocket) {
                CPPJSLIB_LOG("Calling js function via server sent events: " + str);

                try {
                    eventDispatcher->send_event(str);
                } catch (...) {
                    CPPJSLIB_ERR("Could not call the function via server sent events");
                    return;
                }
            } else {
                CPPJSLIB_LOG("Calling js function via websocket: " + str);

                // Send request to all clients
                CPPJSLIB_LOG("Sending request");
                for (const auto &it : *websocketConnections) {
                    try {
                        websocketTLSServer->send(it, str, websocketpp::frame::opcode::value::text);
                    } catch (...) {
                        CPPJSLIB_ERR("Could not send message");
                        return;
                    }
                }

                if (fallback_plain_port) {
                    CPPJSLIB_LOG("Sending message to websocket plain fallback server");
                    for (const auto &it : *websocketFallbackConnections) {
                        try {
                            websocketFallbackServer->send(it, str, websocketpp::frame::opcode::value::text);
                        } catch (...) {
                            CPPJSLIB_ERR("Could not send message");
                            return;
                        }
                    }
                }
            }
#   else
            CPPJSLIB_LOG("Calling js function via server sent events: " + str);

            try {
                eventDispatcher->send_event(str);
            } catch (std::exception &) {
                CPPJSLIB_ERR("Could not call the function via server sent events");
                return;
            }
#   endif //CPPJSLIB_ENABLE_WEBSOCKET
            {
                std::unique_lock<std::mutex> lock(callbacksMutex);
                javascriptCallbacks.insert(std::pair<std::string, callback_function>(callback, callback_func));
            }
        }

#   ifdef CPPJSLIB_ENABLE_WEBSOCKET
        enum tls_mode {
            MOZILLA_INTERMEDIATE = 1, MOZILLA_MODERN = 2
        };

        std::string password;

        void setPassword() {
            if (password.empty()) {
                std::random_device rd;
                static std::mt19937 eng(rd());
                std::uniform_int_distribution<> d(1, 36);
                const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
                for (int i = 0; i < 30; i++) {
                    int rnd = d(eng) - 1;
                    if (rnd < 10) {
                        password.append(std::to_string(rnd));
                    } else {
                        rnd -= 10;
                        password += alphabet[rnd];
                    }
                }
            }
        }

        static void on_http(const std::shared_ptr<util::wspp::server_tls> &s, websocketpp::connection_hdl hdl) {
            util::wspp::server_tls::connection_ptr con = s->get_con_from_hdl(std::move(hdl));

            con->set_body("");
            con->set_status(websocketpp::http::status_code::ok);
        }

        inline util::wspp::context_ptr
        on_tls_init(tls_mode mode, const websocketpp::connection_hdl &, const std::string &cert_path,
                    const std::string &private_key_path) {
            namespace asio = websocketpp::lib::asio;

            CPPJSLIB_LOG(std::string("using TLS mode: ") +
                         (mode == MOZILLA_MODERN ? "Mozilla Modern" : "Mozilla Intermediate"));
            util::wspp::context_ptr ctx =
                    websocketpp::lib::make_shared<asio::ssl::context>(asio::ssl::context::sslv23);

            try {
                if (mode == MOZILLA_MODERN) {
                    // Modern disables TLSv1
                    ctx->set_options(asio::ssl::context::default_workarounds |
                                     asio::ssl::context::no_sslv2 | asio::ssl::context::no_sslv3 |
                                     asio::ssl::context::no_tlsv1 |
                                     asio::ssl::context::single_dh_use);
                } else {
                    ctx->set_options(asio::ssl::context::default_workarounds |
                                     asio::ssl::context::no_sslv2 | asio::ssl::context::no_sslv3 |
                                     asio::ssl::context::single_dh_use);
                }
                ctx->set_password_callback([this](auto, auto) { return password; });
                ctx->use_certificate_chain_file(cert_path);
                ctx->use_private_key_file(private_key_path, boost::asio::ssl::context::pem);

                std::string ciphers;

                if (mode == MOZILLA_MODERN) {
                    ciphers =
                            "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-"
                            "AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-"
                            "SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:"
                            "ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:"
                            "ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-"
                            "SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:"
                            "DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-"
                            "RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK";
                } else {
                    ciphers = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-"
                              "AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-"
                              "SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-"
                              "SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-"
                              "AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-"
                              "RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-"
                              "AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-"
                              "AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:"
                              "AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-"
                              "CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-"
                              "DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA";
                }

                if (SSL_CTX_set_cipher_list(ctx->native_handle(), ciphers.c_str()) != 1) {
                    CPPJSLIB_ERR("Error setting cipher list");
                }
            } catch (std::exception &e) {
                CPPJSLIB_ERR(std::string("Exception: ") + e.what());
            }
            return ctx;
        }

        void initWebsocketTLS(const std::shared_ptr<util::wspp::server_tls> &s, const std::string &cert_path,
                              const std::string &private_key_path) {
            try {
                s->set_http_handler([s](const websocketpp::connection_hdl &hdl) {
                    return on_http(s, hdl);
                });

                s->set_tls_init_handler(
                        [cert_path, private_key_path, this](const websocketpp::connection_hdl &hdl) {
                            return on_tls_init(MOZILLA_INTERMEDIATE, hdl, cert_path, private_key_path);
                        });
            } catch (websocketpp::exception const &e) {
                CPPJSLIB_ERR(e.what());
            } catch (...) {
                CPPJSLIB_ERR("An unknown exception occurred");
            }
        }

#   endif //CPPJSLIB_ENABLE_WEBSOCKET

        uint16_t fallback_plain_port; // The websocket plain fallback server port

        std::shared_ptr<websocket_ssl_type> websocketTLSServer; // The websocket tls server
        std::shared_ptr<websocket_fallback_type> websocketFallbackServer; // The websocket plain fallback server
        // The websocket plain fallback server connection list
        std::shared_ptr<websocket_fallback_connections_type> websocketFallbackConnections;
    };

#endif //CPPJSLIB_ENABLE_HTTPS
} // namespace markusjx::CppJsLib

// Un-define everything that was defined previously

#undef CPPJSLIB_UNUSED
#undef CPPJSLIB_NODISCARD
#undef CPPJSLIB_LOG
#undef CPPJSLIB_ERR
#undef CPPJSLIB_WARN

#ifdef CPPJSLIB_WINDOWS
#   undef CPPJSLIB_WINDOWS
#endif //CPPJSLIB_WINDOWS

#ifdef CPPJSLIB_UNIX
#   undef CPPJSLIB_UNIX
#endif //CPPJSLIB_UNIX

#endif //MARKUSJX_CPPJSLIB_HPP