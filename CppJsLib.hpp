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
#include <json.hpp>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <type_traits>
#include <future>
#include <utility>
#include <memory>

#ifdef CPPJSLIB_ENABLE_WEBSOCKET

#   include <set>
#   include <websocketpp/server.hpp>

#   ifdef CPPJSLIB_ENABLE_HTTPS

#       include <websocketpp/config/asio.hpp>

#   else

#       include <websocketpp/config/asio_no_tls.hpp>

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
#define import(func) importFunction(func, #func)

namespace markusjx::cppJsLib {
    const char localhost[10] = "localhost";

    namespace exceptions {
        class CppJsLibException : public std::exception {
        public:
            inline explicit CppJsLibException(std::string msg) : std::exception(), exceptionType("CppJsLibException"),
                                                                 message(std::move(msg)) {}

            CPPJSLIB_NODISCARD inline const char *getExceptionType() const noexcept { return exceptionType; }

            CPPJSLIB_NODISCARD inline const char *what() const noexcept override { return message.c_str(); }

        protected:
            CppJsLibException(const char *exceptionType, std::string msg)
                    : std::exception(), exceptionType(exceptionType), message(std::move(msg)) {}

        private:
            const char *exceptionType;
            const std::string message;
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
        static bool port_is_in_use(const char *addr, unsigned short port, int &err) {
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
        static std::string gen_random(const int len) {
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
            inline EventDispatcher() : clients(0), id_(0), cid_(-1) {}

            /**
             * Wait for an event
             *
             * @param sink the data sink we are listening on
             */
            inline void wait_event(httplib::DataSink *sink) {
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
            inline void send_event(const std::string &message) {
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
#ifdef CPPJSLIB_ENABLE_HTTPS
        namespace wspp {
            typedef websocketpp::server<websocketpp::config::asio> server;
            typedef websocketpp::server<websocketpp::config::asio_tls> server_tls;
            typedef websocketpp::lib::shared_ptr<websocketpp::lib::asio::ssl::context> context_ptr;
        }// namespace wspp

#else
        namespace wspp {
            typedef websocketpp::server<websocketpp::config::asio> server;
        }
#endif//CPPJSLIB_ENABLE_HTTPS

        namespace wspp {
            typedef std::set<websocketpp::connection_hdl,
                    std::owner_less<websocketpp::connection_hdl>>
                    con_list;
        }

        using websocketpp::lib::bind;

#ifdef CPPJSLIB_ENABLE_HTTPS
        enum tls_mode {
            MOZILLA_INTERMEDIATE = 1, MOZILLA_MODERN = 2
        };

        static std::string password;

        static std::string get_password() { return password; }

        static void setPassword() {
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

        static void on_http(const std::shared_ptr<wspp::server_tls> &s, websocketpp::connection_hdl hdl) {
            wspp::server_tls::connection_ptr con = s->get_con_from_hdl(std::move(hdl));

            con->set_body("");
            con->set_status(websocketpp::http::status_code::ok);
        }

        static wspp::context_ptr
        on_tls_init(tls_mode mode, const websocketpp::connection_hdl &, const std::string &cert_path,
                    const std::string &private_key_path, const std::function<void(std::string)> &log,
                    const std::function<void(std::string)> &err) {
            namespace asio = websocketpp::lib::asio;

            CPPJSLIB_LOG(std::string("using TLS mode: ") +
                         (mode == MOZILLA_MODERN ? "Mozilla Modern" : "Mozilla Intermediate"));
            wspp::context_ptr ctx =
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
                ctx->set_password_callback([](auto, auto) { return get_password(); });
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

        static void initWebsocketTLS(const std::shared_ptr<wspp::server_tls> &s,
                                     const std::string &cert_path,
                                     const std::string &private_key_path, const std::function<void(std::string)> &log,
                                     const std::function<void(std::string)> &err) {
            try {
                s->set_http_handler([s](const websocketpp::connection_hdl &hdl) {
                    return on_http(s, hdl);
                });

                s->set_tls_init_handler(
                        [cert_path, private_key_path, &log, &err](const websocketpp::connection_hdl &hdl) {
                            return on_tls_init(MOZILLA_INTERMEDIATE, hdl, cert_path, private_key_path, log, err);
                        });
            } catch (websocketpp::exception const &e) {
                CPPJSLIB_ERR(e.what());
            } catch (...) {
                CPPJSLIB_ERR("An unknown exception occurred");
            }
        }

#endif//CPPJSLIB_ENABLE_HTTPS

        /**
         * Init a websocket server
         *
         * @tparam EndpointType the endpoint type
         * @param s the server to initialize
         * @param list the connection list
         * @param err the error logger
         */
        template<typename EndpointType>
        static void initWebsocketServer(std::shared_ptr<EndpointType> s, const std::shared_ptr<wspp::con_list> &list,
                                        const std::function<void(const std::string &)> &err) {
            try {
                s->set_open_handler([list](const websocketpp::connection_hdl &hdl) {
                    list->insert(hdl);
                });

                s->set_close_handler([list](const websocketpp::connection_hdl &hdl) {
                    list->erase(hdl);
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
        static void startWebsocketServer(std::shared_ptr<EndpointType> s, const std::string &host, int port,
                                         const std::function<void(const std::string &)> &err,
                                         const std::function<void(const std::string &)> &log) {
            CPPJSLIB_LOG("Starting websocket to listen on host " + host + " and port " + std::to_string(port));
            try {
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
        static void onMessage(std::shared_ptr<Endpoint> s,
                              const std::function<void(const std::string &)> &err,
                              const std::function<void(const std::string &)> &log,
                              const std::function<std::string(std::string)> &messageHandler,
                              websocketpp::connection_hdl hdl, const wspp::server::message_ptr &msg) {
            try {
                CPPJSLIB_LOG("Received data: " + msg->get_payload());
                std::string toSend = messageHandler(msg->get_payload());
                if (!toSend.empty()) {
                    s->send(hdl, toSend, websocketpp::frame::opcode::text);
                }
            } catch (std::exception &e) {
                CPPJSLIB_ERR("Websocket receive failed: " + std::string(e.what()));
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
         * @param err the error logger
         * @param log the logging function
         * @param messageHandler the message handler function
         * @return whether the server could be started
         */
        template<typename Endpoint>
        static bool startNoWeb_f(std::shared_ptr<Endpoint> ws_server, const std::string &host, int port, bool block,
                                 const std::function<void(const std::string &)> &err,
                                 const std::function<void(const std::string &)> &log,
                                 const std::function<std::string(std::string)> &messageHandler) {
            ws_server->set_message_handler(
                    [&ws_server, &err, &log, &messageHandler](auto &&PH1, auto &&PH2) {
                        return onMessage<Endpoint>(ws_server, err, log, messageHandler,
                                                   std::forward<decltype(PH1)>(PH1), std::forward<decltype(PH2)>(PH2));
                    });

            if (block) {
                CPPJSLIB_LOG("Starting websocket server in blocking mode");
                startWebsocketServer(ws_server, host, port, err, log);
            } else {
                CPPJSLIB_LOG("Starting websocket server in non-blocking mode");
                std::thread websocketThread([&ws_server, port, &host, &err, &log] {
                    startWebsocketServer(ws_server, host, port, err, log);
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

#endif//CPPJSLIB_ENABLE_WEBSOCKET
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
        inline explicit ResponseValue(const T &val) : value(std::make_shared<T>(val)), exception(nullptr) {}

        /**
         * Create a response value with an exception
         *
         * @param e_ptr the exception pointer
         */
        inline explicit ResponseValue(std::exception_ptr e_ptr) : value(nullptr), exception(std::move(e_ptr)) {}

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
        explicit inline Response() : _data(std::make_shared<responseVector<T>>()), mtx(std::make_shared<std::mutex>()),
                                     cv_mtx(std::make_shared<std::mutex>()),
                                     cv(std::make_shared<std::condition_variable>()),
                                     finished(std::make_shared<std::atomic_bool>(false)) {}

        /**
         * Push a value to the response values
         *
         * @param val the value to push
         */
        inline void push_back(const T &val) const {
            std::unique_lock<std::mutex> lock(*mtx);
            _data->push_back(ResponseValue<T>(val));
        }

        /**
         * Push an exception pointer to the response values
         *
         * @param e_ptr the exception pointer to push
         */
        inline void push_back(const std::exception_ptr &e_ptr) const {
            std::unique_lock<std::mutex> lock(*mtx);
            _data->push_back(ResponseValue<T>(e_ptr));
        }

        /**
         * Get a value at an index
         *
         * @param i the index
         * @return the value at i
         */
        CPPJSLIB_NODISCARD inline ResponseValue<T> at(const size_t i) const {
            std::unique_lock<std::mutex> lock(*mtx);
            return _data->at(i);
        }

        /**
         * Get a value at an index
         *
         * @param i the index
         * @return the value at i
         */
        CPPJSLIB_NODISCARD inline ResponseValue<T> operator[](const size_t i) const {
            return this->at(i);
        }

        CPPJSLIB_NODISCARD inline typename responseVector<T>::const_iterator begin() const {
            return _data->begin();
        }

        CPPJSLIB_NODISCARD inline typename responseVector<T>::const_iterator end() const {
            return _data->end();
        }

        /**
         * Get the response values
         *
         * @return a current copy of the data
         */
        CPPJSLIB_NODISCARD inline responseVector<T> data() const {
            std::unique_lock<std::mutex> lock(*mtx);
            return responseVector<T>(*_data);
        }

        /**
         * Get the current number of values stored
         *
         * @return the number of values stored
         */
        CPPJSLIB_NODISCARD inline size_t size() const {
            std::unique_lock<std::mutex> lock(*mtx);
            return _data->size();
        }

        /**
         * Check if there are values stored
         *
         * @return true, if the value vector is not empty
         */
        CPPJSLIB_NODISCARD CPPJSLIB_UNUSED inline bool has_data() const {
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
        CPPJSLIB_UNUSED CPPJSLIB_NODISCARD inline std::cv_status
        wait_for(const std::chrono::duration<R, Period> &time) const {
            std::unique_lock<std::mutex> lock(*cv_mtx);
            return cv->wait_for(lock, time, [this] {
                return finished->operator bool();
            });
        }

        /**
         * Mark all responses received
         */
        inline void resolve() const {
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

    /**
     * The main CppJsLib server
     */
    class Server {
    public:
        // Set the websocket types
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
        using websocket_con_list = util::wspp::con_list;
        using websocket_type = util::wspp::server;
#   ifdef CPPJSLIB_ENABLE_HTTPS
        using websocket_fallback_type = util::wspp::server;
        using websocket_fallback_connections_type = util::wspp::con_list;
        using websocket_ssl_type = util::wspp::server_tls;
#   else
        using websocket_fallback_type = void;
        using websocket_fallback_connections_type = void;
        using websocket_ssl_type = void;
#   endif//CPPJSLIB_ENABLE_HTTPS
#else
        using websocket_con_list = void;
        using websocket_type = void;
        using websocket_fallback_type = void;
        using websocket_fallback_connections_type = void;
        using websocket_ssl_type = void;
#endif//CPPJSLIB_ENABLE_WEBSOCKET

        /**
         * Initialize the server
         *
         * @param base_dir the base directory
         */
        explicit inline Server(std::string base_dir = ".") : check_ports(true), ssl(false), _running(false),
                                                             stopped(true), base_dir(std::move(base_dir)),
                                                             fallback_plain_port(0) {
            // Create the web server
            webServer = std::make_shared<httplib::Server>();
            webServer->set_mount_point("/", this->base_dir.c_str());

            // Set the message handler
            webServer->Post("/cppjslib", [this](const httplib::Request &req, httplib::Response &res) {
                std::string toSend = this->handleMessages(req.body);
                if (!toSend.empty()) {
                    res.set_content(toSend, "text/plain");
                }
                res.status = 200;
            });

            // Create the event dispatcher
            eventDispatcher = std::make_shared<util::EventDispatcher>();

            websocket_only = false;
            no_websocket = false;

            log = [](const std::string &) {};
            err = log;

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
#ifdef CPPJSLIB_ENABLE_HTTPS
            util::setPassword();
#endif //CPPJSLIB_ENABLE_HTTPS

            CPPJSLIB_LOG("Initializing websocket server");
            websocketServer = std::make_shared<util::wspp::server>();
            websocketConnections = std::make_shared<util::wspp::con_list>();

            util::initWebsocketServer(websocketServer, websocketConnections, err);
#endif //CPPJSLIB_ENABLE_WEBSOCKET
        }

#ifdef CPPJSLIB_ENABLE_HTTPS

        inline Server(std::string base_dir, const std::string &cert_path, const std::string &private_key_path,
                      uint16_t fallback_plain_port = true) : ssl(true), check_ports(true), _running(false),
                                                             stopped(true), base_dir(std::move(base_dir)),
                                                             fallback_plain_port(fallback_plain_port) {
            if (cert_path.empty() || private_key_path.empty()) {
                throw exceptions::InvalidArgumentsException(
                        "The certificate or private key paths were empty");
            }

            websocket_only = false;
            no_websocket = false;

            webServer = std::make_shared<httplib::SSLServer>(cert_path.c_str(), private_key_path.c_str());
            webServer->set_mount_point("/", this->base_dir.c_str());

            // Set the message handler
            webServer->Post("/cppjslib", [this](const httplib::Request &req, httplib::Response &res) {
                res.set_content(this->handleMessages(req.body), "text/plain");
            });

            eventDispatcher = std::make_shared<util::EventDispatcher>();

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
            util::setPassword();

            CPPJSLIB_LOG("Initializing tls websocket server");
            websocketConnections = std::make_shared<websocket_con_list>();
            websocketTLSServer = std::make_shared<websocket_ssl_type>();
            util::initWebsocketTLS(websocketTLSServer, cert_path, private_key_path, log, err);
            util::initWebsocketServer(websocketTLSServer, websocketConnections, err);

            if (fallback_plain_port) {
                CPPJSLIB_LOG("Initializing websocket plain fallback server");
                websocketFallbackServer = std::make_shared<websocket_fallback_type>();
                websocketFallbackConnections = std::make_shared<websocket_fallback_connections_type>();
                util::initWebsocketServer(websocketFallbackServer, websocketFallbackConnections, err);
            }
#endif//CPPJSLIB_ENABLE_WEBSOCKET
        }

#endif //CPPJSLIB_ENABLE_HTTPS

#ifdef CPPJSLIB_ENABLE_WEBSOCKET

        /**
         * Copying this doesn't make any sense, don't do it
         */
        Server(const Server &) = delete;

        /**
         * Copying this doesn't make any sense, don't do it
         */
        Server &operator=(const Server &) = delete;

        /**
         * Start without the web server (websocket only)
         *
         * @param port the websocket port to listen on
         * @param host the host address
         * @param block whether to block after starting the server
         * @return true, if the server could be started
         */
        inline bool startNoWeb(uint16_t port, const std::string &host = "localhost", bool block = true) {
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

#   ifdef CPPJSLIB_ENABLE_HTTPS
            if (websocketFallbackServer) {
                CPPJSLIB_LOG("Starting websocket plain fallback server");
                util::startNoWeb_f(websocketFallbackServer, host, fallback_plain_port, block, err, log,
                                   [this](const std::string &msg) {
                                       return this->handleMessages(msg);
                                   });
            }

            if (ssl) {
                CPPJSLIB_LOG("Starting websocket tls server");
                _running = util::startNoWeb_f(websocketServer, host, port, block, err, log,
                                              [this](const std::string &msg) {
                                                  return this->handleMessages(msg);
                                              });
                return _running;
            } else {
                CPPJSLIB_LOG("Starting websocket server");
                _running = util::startNoWeb_f(websocketServer, host, port, block, err, log,
                                              [this](const std::string &msg) {
                                                  return this->handleMessages(msg);
                                              });
                return _running;
            }
#   else
            CPPJSLIB_LOG("Starting websocket server");
            _running = util::startNoWeb_f(websocketServer, host, port, block, err, log,
                                          [this](const std::string &msg) {
                                              return this->handleMessages(msg);
                                          });

            return _running;
#   endif //CPPJSLIB_ENABLE_HTTPS
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
        inline bool startNoWebSocket(uint16_t port, const std::string &host = localhost, bool block = true) {
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
            init_ws_json["ws"] = "false";
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
        inline bool
        start(uint16_t port, const std::string &host = localhost, uint16_t websocketPort = 0, bool block = true) {
            if (websocket_only) {
                throw exceptions::CppJsLibException("The Server is already started in websocket-only mode");
            }

            if (_running) {
                throw exceptions::CppJsLibException("The Server is already running");
            }

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
            // If the port is zero, don't start the web server
            if (port == 0) {
                return startNoWeb(websocketPort, host, true);
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
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
            init_ws_json["ws"] = true;
            init_ws_json["host"] = host;
            init_ws_json["port"] = websocketPort;
#   ifdef CPPJSLIB_ENABLE_HTTPS
            if (ssl) {
                init_ws_json["tls"] = true;
                if (fallback_plain_port) {
                    init_ws_json["fallback_plain"] = true;
                    init_ws_json["fallback_plain_port"] = fallback_plain_port;
                } else {
                    init_ws_json["fallback_plain"] = false;
                }
            } else {
                init_ws_json["tls"] = false;
            }
#   else
            init_ws_json["tls"] = false;
#   endif //CPPJSLIB_ENABLE_HTTPS
#else
            init_ws_json["ws"] = false;
#endif //CPPJSLIB_ENABLE_WEBSOCKET

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
#   ifdef CPPJSLIB_ENABLE_HTTPS
            if (ssl) {
                log("Starting tls websocket server");
                wsRunning = util::startNoWeb_f(websocketTLSServer, host, websocketPort, false, err, log,
                                               [this](const std::string &msg) {
                                                   return this->handleMessages(msg);
                                               });
            } else {
                log("Starting websocket server");
                wsRunning = util::startNoWeb_f(websocketServer, host, websocketPort, false, err, log,
                                               [this](const std::string &msg) {
                                                   return this->handleMessages(msg);
                                               });
            }

            if (fallback_plain_port) {
                log("Starting websocket plain fallback server");
                wsRunning =
                        wsRunning &&
                        util::startNoWeb_f(websocketFallbackServer, host, fallback_plain_port, false, err, log,
                                           [this](const std::string &msg) {
                                               return this->handleMessages(msg);
                                           });
            }
#   else
            CPPJSLIB_LOG("Starting websocket server");
            wsRunning = util::startNoWeb_f(websocketServer, host, websocketPort, false, err, log,
                                           [this](const std::string &msg) {
                                               return this->handleMessages(msg);
                                           });
#   endif //CPPJSLIB_ENABLE_HTTPS
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
        inline void start(std::promise<bool> &promise, uint16_t port, const std::string &host = localhost,
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
        inline void exportFunction(const std::function<R(Args...)> &func, const std::string &name) {
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
        inline void exportFunction(R (&func)(Args...), const std::string &name) {
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
         */
        template<class R, class...Args>
        inline void importFunction(std::function<R(Args...)> &func, const std::string &name) {
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
        inline void importFunction(std::function<void(std::promise<R> &, Args...)> &func, const std::string &name) {
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
        inline void importFunction(std::function<Response<R>(Args...)> &func, const std::string &name) {
            func = [this, name](Args...args) {
                if (!this->running()) {
                    throw exceptions::CppJsLibException("No server is running");
                }

                // Convert the arguments to json
                nlohmann::json json = argsToJson(args...);

                Response<R> response;
                callJavascriptFunction(json, name, callback_function([response](const nlohmann::json &data) {
                    response.push_back(data.get<R>());
                }, [response](const std::exception_ptr &ptr) {
                    response.push_back(ptr);
                }, [this, response] {
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
                    if (!no_websocket) {
#   ifdef CPPJSLIB_ENABLE_HTTPS
                        if (response.size() == (websocketConnections->size() + websocketFallbackConnections->size())) {
                            response.resolve();
                            return true;
                        }
#   else
                        if (response.size() == websocketConnections->size()) {
                            response.resolve();
                            return true;
                        }
#   endif //CPPJSLIB_ENABLE_HTTPS
                    }
#else
                    if (response.size() == eventDispatcher->clients) {
                        response.resolve();
                        return true;
                    }
#endif //CPPJSLIB_ENABLE_WEBSOCKET
                    return false;
                }));

                return response;
            };
        };

        /**
         * Check if the servers are running
         *
         * @return true, if they are running
         */
        CPPJSLIB_NODISCARD inline bool running() const {
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
            if (websocket_only) {
#   ifdef CPPJSLIB_ENABLE_HTTPS
                if (ssl) {
                    return websocketTLSServer->is_listening();
                } else {
                    return websocketServer->is_listening();
                }
#   else
                return websocketServer->is_listening();
#   endif //CPPJSLIB_ENABLE_HTTPS
            } else {
                if (no_websocket) {
#   ifdef CPPJSLIB_ENABLE_HTTPS
                    if (ssl) {
                        return websocketTLSServer->is_listening();
                    } else {
                        return websocketServer->is_listening();
                    }
#   else
                    return websocketServer->is_listening();
#   endif //CPPJSLIB_ENABLE_HTTPS
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
        void stop() {
            if (running()) {
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
                if (!websocket_only) {
                    CPPJSLIB_LOG("Stopping web server");
                    webServer->stop();
                }
//#   endif //CPPJSLIB_ENABLE_HTTPS

                CPPJSLIB_LOG("Stopping websocket server");
                try {
#   ifdef CPPJSLIB_ENABLE_HTTPS
                    if (ssl) {
                        websocketTLSServer->stop_listening();
                        websocketTLSServer->stop();
                    } else {
                        websocketServer->stop_listening();
                        websocketServer->stop();
                    }

                    if (fallback_plain_port) {
                        CPPJSLIB_LOG("Stopping websocket plain fallback server");
                        websocketFallbackServer->stop_listening();
                        websocketFallbackServer->stop();
                    }
#   else
                    websocketServer->stop_listening();
                    websocketServer->stop();
#   endif //CPPJSLIB_ENABLE_HTTPS
                } catch (...) {
                    CPPJSLIB_ERR("Could not close websocket server(s)");
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
        inline void setLogger(std::function<void(std::string)> fn) {
            log = std::move(fn);
        }

        /**
         * Set the error logging function
         *
         * @param fn the logging function
         */
        inline void setError(std::function<void(std::string)> fn) {
            err = std::move(fn);
        }

        /**
         * Get the http server
         *
         * @return the http server
         */
        CPPJSLIB_UNUSED CPPJSLIB_NODISCARD inline std::shared_ptr<httplib::Server> getHttpServer() const {
            return webServer;
        }

        /**
         * Get the websocket server
         *
         * @return the websocket server
         */
        CPPJSLIB_UNUSED CPPJSLIB_NODISCARD inline std::shared_ptr<websocket_type> getWebsocketServer() const {
            return websocketServer;
        }

        /**
         * Get the websocket tls server
         *
         * @return the websocket tls server
         */
        CPPJSLIB_UNUSED CPPJSLIB_NODISCARD inline std::shared_ptr<websocket_ssl_type> getWebsocketTLSServer() const {
            return websocketTLSServer;
        }

        /**
         * Get the websocket fallback server
         *
         * @return the websocket fallback server
         */
        CPPJSLIB_UNUSED CPPJSLIB_NODISCARD inline std::shared_ptr<websocket_fallback_type>
        getWebsocketFallbackServer() const {
            return websocketFallbackServer;
        }

        /**
         * Delete the server instance
         */
        inline ~Server() {
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
    private:
        using PostHandler = std::function<nlohmann::json(nlohmann::json req_body)>;

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
            inline callback_function(std::function<void(nlohmann::json)> callback,
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
         * Handle messages from js
         *
         * @param msg the message to parse
         * @return the result
         */
        inline std::string handleMessages(const std::string &msg) {
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
                    return std::string();
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
                    return std::string();
                }

                if (json.find("callback") == json.end()) {
                    CPPJSLIB_ERR("json structure had no callback");
                    return std::string();
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
                    return std::string();
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

            return std::string();
        }

        /**
         * Initialize the server sent event listener
         */
        inline void addSseListener() {
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
        inline void addInitHandlers(const std::string &init_ws_string) {
            nlohmann::json initList;
            for (const auto &p: initMap) {
                initList[p.first] = p.second;
            }
            initMap.clear();

            initString = initList.dump();
            const auto initHandler = [this](const httplib::Request &, httplib::Response &res) {
                res.set_content(initString, "text/plain");
            };

            const auto init_ws_handler = [init_ws_string](const httplib::Request &, httplib::Response &res) {
                res.set_content(init_ws_string, "text/plain");
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
        inline void startWebServer(uint16_t port, const std::string &host, bool block) {
            std::function < void() > func;
            func = [&host, port, this]() {
                if (!webServer->listen(host.c_str(), port)) {
                    CPPJSLIB_ERR("Could not start web server");
                    _running = false;
                }

                stopped = true;
            };

            if (!block) {
                CPPJSLIB_LOG("Starting web server in non-blocking mode");
                std::thread t(func);
                t.detach();

                // Sleep for one second, so the servers can fail
                CPPJSLIB_LOG("Sleeping for a short while");
                std::this_thread::sleep_for(std::chrono::seconds(1));
            } else {
                CPPJSLIB_LOG("Starting web server in blocking mode");
                func();
            }
        }

        /**
         * Call a javascript function
         *
         * @param args the function argument json array
         * @param funcName the function name
         * @param promise the promise to be resolved when the call finished
         */
        inline void callJavascriptFunction(const nlohmann::json &args, const std::string &funcName,
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
                while (javascriptCallbacks.count(callback) != 0) {
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
                for (const auto &it : *websocketConnections) {
                    try {
#   ifdef CPPJSLIB_ENABLE_HTTPS
                        if (ssl) {
                            websocketTLSServer->send(it, str, websocketpp::frame::opcode::value::text);
                        } else {
                            websocketServer->send(it, str, websocketpp::frame::opcode::value::text);
                        }
#   else
                        websocketServer->send(it, str, websocketpp::frame::opcode::value::text);
#   endif //CPPJSLIB_ENABLE_HTTPS
                    } catch (...) {
                        CPPJSLIB_ERR("Could not send message");
                        return;
                    }
                }

#   ifdef CPPJSLIB_ENABLE_HTTPS
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
#   endif //CPPJSLIB_ENABLE_HTTPS
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

        /**
         * Add a exported function to the websocketTargets map
         *
         * @param name the function name
         * @param fn the function
         */
        inline void callFuncFromJs(const std::string &name, const PostHandler &fn) {
            websocketTargets.insert(std::pair<std::string, PostHandler>(name, fn));
        }

        CPPJSLIB_UNUSED const bool ssl; // Whether to use ssl
        bool websocket_only; // Whether this is websocket only
        bool no_websocket; // Whether websocket is disabled
        bool _running, stopped; // Whether the servers are running or stopped
        std::string base_dir; // The web base directory
        std::string initString; // The init string. Contains all exported functions in a json array as a string.
        CPPJSLIB_UNUSED uint16_t fallback_plain_port; // The websocket plain fallback server port

        // The function initializer map.
        // Contains the function name as a key
        // and the number of arguments as a value.
        std::map<std::string, size_t> initMap;

        // The javascript callbacks. Used for when the js functions return values.
        // Has a random string as a key, used to identify the callback
        // and a reference to a promise to be resolved.
        std::map<std::string, callback_function> javascriptCallbacks;
        std::mutex callbacksMutex;

        // The websocket target functions
        std::map<std::string, PostHandler> websocketTargets;

        // The logging and error functions
        std::function<void(std::string)> log, err;

        // The http(s) server
        std::shared_ptr<httplib::Server> webServer;

        // The event dispatcher as an alternative to websockets
        std::shared_ptr<util::EventDispatcher> eventDispatcher;

        std::shared_ptr<websocket_type> websocketServer; // The websocket server
        std::shared_ptr<websocket_ssl_type> websocketTLSServer; // The websocket tls server
        std::shared_ptr<websocket_fallback_type> websocketFallbackServer; // The websocket plain fallback server
        std::shared_ptr<websocket_con_list> websocketConnections; // The websocket connection list
        // The websocket plain fallback server connection list
        std::shared_ptr<websocket_fallback_connections_type> websocketFallbackConnections;
    };
}// namespace markusjx::CppJsLib

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