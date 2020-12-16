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
#elif defined(__LINUX__) || defined(__APPLE__) || defined (__CYGWIN__) || defined(__linux__) || defined(__FreeBSD__) || defined(unix) || defined(__unix) || defined(__unix__)
#   define CPPJSLIB_UNIX
#   undef CPPJSLIB_WINDOWS
#endif

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

namespace markusjx::CppJsLib {
    const char localhost[10] = "localhost";

    namespace exceptions {
        class CppJsLibException : public std::exception {
        public:
            inline explicit CppJsLibException(std::string msg) : message(std::move(msg)),
                                                                 exceptionType("CppJsLibException"), std::exception() {}

            CPPJSLIB_NODISCARD inline const char *getExceptionType() const noexcept { return exceptionType; }

            CPPJSLIB_NODISCARD inline const char *what() const noexcept override { return message.c_str(); }

        protected:
            CppJsLibException(const char *exceptionType, std::string msg)
                    : message(std::move(msg)), exceptionType(exceptionType), std::exception() {}

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

    namespace util {
        static bool port_is_in_use(const char *addr, unsigned short port, int &err) {
#ifdef CPPJSLIB_WINDOWS
            WSADATA wsaData;
            auto ConnectSocket = INVALID_SOCKET;
            struct addrinfo *result = nullptr,
                    *ptr = nullptr,
                    hints{};

            // Initialize Winsock
            err = WSAStartup(MAKEWORD(2, 2), &wsaData);
            if (err != 0) {
                //errorF("WSAStartup failed with error: " + std::to_string(err));
                return false;
            }

            ZeroMemory(&hints, sizeof(hints));
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;

            // Resolve the server address and port
            err = getaddrinfo(addr, std::to_string(port).c_str(), &hints, &result);
            if (err != 0) {
                //errorF("getaddrinfo failed with error: " + std::to_string(err));
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
                    //errorF("Socket failed with error: " + std::to_string(err));
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
                //loggingF("Unable to connect to server. Port is not in use");
                WSACleanup();
                return false;
            }

            // shutdown the connection since no more data will be sent
            err = shutdown(ConnectSocket, SD_SEND);
            if (err == SOCKET_ERROR) {
                err = WSAGetLastError();
                //errorF("Shutdown failed with error: " + std::to_string(err));
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
                //errorF("Socket creation error");
                err = -1;
                return false;
            }

            serv_addr.sin_family = AF_INET;
            serv_addr.sin_port = htons(port);

            // Convert IPv4 and IPv6 addresses from text to binary form
            if (inet_pton(AF_INET, addr, &serv_addr.sin_addr) <= 0) {
                //errorF("Invalid address/ Address not supported");
                err = -1;
                return false;
            }

            err = connect(sock, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
            if (err < 0) {
                //errorF("Connection failed. Port is not in use");
                err = 0;
                return false;
            }

            close(sock);
            return true;
#endif //CPPJSLIB_WINDOWS
        }

        // Source: https://stackoverflow.com/a/440240
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
            inline EventDispatcher() {
                id_ = 0;
                cid_ = -1;
                connectedClients = 0;
            }

            inline void wait_event(httplib::DataSink *sink) {
                std::unique_lock<std::mutex> lk(m_);
                int id = id_;
                cv_.wait(lk, [&] {
                    return cid_ == id;
                });

                if (sink->is_writable()) {
                    sink->write(message_.data(), message_.size());
                }
            }

            inline void send_event(const std::string &message) {
                {
                    std::lock_guard<std::mutex> lk(m_);
                    cid_ = id_++;
                    message_.clear();
                    message_.reserve(message.size() + 8);
                    message_.append("data: ").append(message).append("\n\n");
                }
                cv_.notify_all();
            }

            inline void clientConnected() {
                client_mtx.lock();
                connectedClients++;
                client_mtx.unlock();
            }

            inline void clientDisconnected() {
                client_mtx.lock();
                if (connectedClients > 0) {
                    connectedClients--;
                }
                client_mtx.unlock();
            }

            inline bool isClientConnected() {
                client_mtx.lock();
                bool connected = connectedClients > 0;
                client_mtx.unlock();

                return connected;
            }

        private:
            std::atomic_int connectedClients;
            std::mutex m_, client_mtx;
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

        void initWebsocketTLS(const std::shared_ptr<wspp::server_tls> &s CPPJSLIB_CERTS);
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
        enum tls_mode { MOZILLA_INTERMEDIATE = 1, MOZILLA_MODERN = 2 };

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

        static void on_http(wspp::server_tls *s, websocketpp::connection_hdl hdl) {
            wspp::server_tls::connection_ptr con = s->get_con_from_hdl(std::move(hdl));

            con->set_body("");
            con->set_status(websocketpp::http::status_code::ok);
        }

        static wspp::context_ptr
        on_tls_init(tls_mode mode, const websocketpp::connection_hdl &hdl CPPJSLIB_CERTS) {
            namespace asio = websocketpp::lib::asio;

            loggingF(std::string("using TLS mode: ") +
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
                ctx->set_password_callback(bind(&get_password));
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
                    errorF("Error setting cipher list");
                }
            } catch (std::exception &e) { errorF(std::string("Exception: ") + e.what()); }
            return ctx;
        }

        static void initWebsocketTLS(const std::shared_ptr<wspp::server_tls> &s,
                                     const std::string &cert_path,
                                     const std::string &private_key_path) {
            try {
                std::function<wspp::context_ptr(tls_mode, websocketpp::connection_hdl)> on_tls =
                        [cert_path, private_key_path](tls_mode mode,
                                                      const websocketpp::connection_hdl &hdl) {
                            return on_tls_init(mode, hdl, cert_path, private_key_path);
                        };

                s->set_http_handler(bind(&on_http, s.get(), std::placeholders::_1));
                s->set_tls_init_handler(bind(on_tls, MOZILLA_INTERMEDIATE, std::placeholders::_1));
            } catch (websocketpp::exception const &e) { errorF(e.what()); } catch (...) {
                errorF("An unknown exception occurred");
            }
        }
#endif//CPPJSLIB_ENABLE_HTTPS

        template<typename EndpointType>
        static void initWebsocketServer(std::shared_ptr<EndpointType> s, const std::shared_ptr<wspp::con_list> &list,
                                        const std::function<void(const std::string &)> &_errorF,
                                        const std::function<void(const std::string &)> &_loggingF) {
            try {
                s->set_open_handler(bind(
                        [list](const websocketpp::connection_hdl &hdl) {
                            list->insert(hdl);
                        },
                        std::placeholders::_1));
                s->set_close_handler(bind(
                        [list](const websocketpp::connection_hdl &hdl) {
                            list->erase(hdl);
                        },
                        std::placeholders::_1));

                s->set_access_channels(websocketpp::log::alevel::all);
                s->clear_access_channels(websocketpp::log::alevel::frame_payload);

                s->init_asio();
            } catch (const std::exception &e) {
                _errorF("Could not initialize websocket server. Error: " + std::string(e.what()));
            } catch (...) {
                _errorF("An unknown exception occurred");
            }
        }

        template<typename EndpointType>
        static void startWebsocketServer(std::shared_ptr<EndpointType> s, const std::string &host, int port,
                                         const std::function<void(const std::string &)> &_errorF,
                                         const std::function<void(const std::string &)> &_loggingF) {
            _loggingF("Starting websocket to listen on host " + host + " and port " + std::to_string(port));
            try {
                s->listen(host, std::to_string(port));
                s->start_accept();

                s->run();
            } catch (const std::exception &e) {
                _errorF("Could not start listening. Error: " + std::string(e.what()));
            } catch (...) {
                _errorF("An unknown exception occurred");
            }
        }

        template<typename Endpoint>
        void onMessage(std::shared_ptr<Endpoint> s,
                       const std::function<void(const std::string &)> &_errorF,
                       const std::function<void(const std::string &)> &_loggingF,
                       const std::function<std::string(std::string)> &messageHandler,
                       websocketpp::connection_hdl hdl, const wspp::server::message_ptr &msg) {
            try {
                _loggingF("Received data: " + msg->get_payload());

                s->send(hdl, messageHandler(msg->get_payload()), websocketpp::frame::opcode::text);
            } catch (std::exception &e) {
                _errorF("Websocket receive failed: " + std::string(e.what()));
            }
        }

        template<typename Endpoint>
        static bool startNoWeb_f(std::shared_ptr<Endpoint> ws_server, const std::string &host, int port, bool block,
                                 const std::function<void(const std::string &)> &_errorF,
                                 const std::function<void(const std::string &)> &_loggingF,
                                 const std::function<std::string(std::string)> &messageHandler) {
            ws_server->set_message_handler(
                    [&ws_server, &_errorF, &_loggingF, &messageHandler](auto &&PH1, auto &&PH2) {
                        return onMessage<Endpoint>(ws_server, _errorF, _loggingF, messageHandler,
                                                   std::forward<decltype(PH1)>(PH1), std::forward<decltype(PH2)>(PH2));
                    });

            if (block) {
                _loggingF("Starting websocket server in blocking mode");
                startWebsocketServer(ws_server, host, port, _errorF, _loggingF);
            } else {
                _loggingF("Starting websocket server in non-blocking mode");
                std::thread websocketThread([&ws_server, port, &host, &_errorF, &_loggingF] {
                    startWebsocketServer(ws_server, host, port, _errorF, _loggingF);
                });
                websocketThread.detach();

                std::this_thread::sleep_for(std::chrono::seconds(1));
            }

            if (ws_server->is_listening()) {
                _loggingF("Successfully started websocket server");
            } else {
                _errorF("Could not start websocket server");
            }

            return ws_server->is_listening();
        }

#endif//CPPJSLIB_ENABLE_WEBSOCKET
    }// namespace util

    class Server {
    public:
        // Set the websocket types
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
        using websocket_con_list = util::wspp::con_list;
        using websocket_type = util::wspp::server;
#   ifdef CPPJSLIB_ENABLE_HTTPS
        using websocket_fallback_type = util::wspp::server;
        using websocket_fallback_connections_type = util::wspp::con_list;
        using websocket_ssl_type = util::wspp::tls_server;
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

        explicit inline Server(std::string base_dir) : base_dir(std::move(base_dir)), ssl(false), check_ports(true),
                                                       fallback_plain_port(0), running(false), stopped(true) {
            webServer = std::make_shared<httplib::Server>();
            webServer->set_mount_point("/", this->base_dir.c_str());

            // Set the message handler
            webServer->Post("/cppjslib", [this](const httplib::Request &req, httplib::Response &res) {
                res.set_content(this->handleMessages(req.body), "text/plain");
                res.status = 200;
            });

            eventDispatcher = std::make_shared<util::EventDispatcher>();

            websocket_only = false;
            no_websocket = false;

            log = [](const std::string &) {};
            err = log;

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
#ifdef CPPJSLIB_ENABLE_HTTPS
            util::setPassword();
#endif //CPPJSLIB_ENABLE_HTTPS

            log("Initializing websocket server");
            websocketServer = std::make_shared<util::wspp::server>();
            websocketConnections = std::make_shared<util::wspp::con_list>();

            util::initWebsocketServer(websocketServer, websocketConnections, err, log);
#endif //CPPJSLIB_ENABLE_WEBSOCKET
        }

#ifdef CPPJSLIB_ENABLE_HTTPS

        inline Server(const std::string &base_dir, const std::string &cert_path, const std::string &private_key_path,
                      uint16_t fallback_plain_port = true) : fallback_plain_port(fallback_plain_port), ssl(true),
                                                             check_ports(true), running(false), stopped(true) {
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
            setPassword();

            //loggingF("Initializing tls websocket server");
            websocketConnections = std::make_shared<util::wspp::con_list>();
            websocketServer = std::make_shared<wspp::server_tls>();
            initWebsocketTLS(websocketServer, cert_path, private_key_path);
            initWebsocketServer(websocketServer, websocketConnections);

            if (fallback_plain) {
                //loggingF("Initializing websocket plain fallback server");
                websocketFallbackServer = std::make_shared<util::wspp::server>();
                websocketFallbackConnections = std::make_shared<util::wspp::con_list>();
                initWebsocketServer(websocketFallbackServer, websocketFallbackConnections);
            }
#endif//CPPJSLIB_ENABLE_WEBSOCKET
        }

#endif //CPPJSLIB_ENABLE_HTTPS

#ifdef CPPJSLIB_ENABLE_WEBSOCKET

        inline bool startNoWeb(uint16_t port, const std::string &host = "localhost", bool block = true) {
            if (check_ports) {
                int error = 0;
                if (util::port_is_in_use("localhost", port, error)) {
                    err("port " + std::to_string(port) + " is already in use");
                    return false;
                } else if (error != 0) {
                    err("port_is_in_use finished with code " + std::to_string(error));
                }
            }

            websocket_only = true;
            no_websocket = false;

#   ifdef CPPJSLIB_ENABLE_HTTPS
            if (websocketFallbackServer) {
                log("Starting websocket plain fallback server");
                util::startNoWeb_f(websocketFallbackServer, host, fallback_plain_port, block, err, log,
                                   [this](const std::string &msg) {
                                       return this->handleMessages(msg);
                                   });
            }

            if (ssl) {
                log("Starting websocket tls server");
                running = util::startNoWeb_f(websocketServer, host, port, block, err, log,
                                             [this](const std::string &msg) {
                                                 return this->handleMessages(msg);
                                             });
                return running;
            } else {
                log("Starting websocket server");
                running = util::startNoWeb_f(websocketServer, host, port, block, err, log,
                                             [this](const std::string &msg) {
                                                 return this->handleMessages(msg);
                                             });
                return running;
            }
#   else
            log("Starting websocket server");
            running = util::startNoWeb_f(websocketServer, host, port, block, err, log,
                                         [this](const std::string &msg) {
                                             return this->handleMessages(msg);
                                         });

            return running;
#   endif //CPPJSLIB_ENABLE_HTTPS
        }

#endif //CPPJSLIB_ENABLE_WEBSOCKET


        inline bool startNoWebSocket(uint16_t port, const std::string &host = localhost, bool block = true) {
            log("Starting without websocket server");

            if (port == 0) {
                throw exceptions::CppJsLibException("Cannot start servers with a negative port number");
            }

            // Check if this is started or websocket-only
            if (websocket_only) {
                throw exceptions::CppJsLibException("The Server is already started in websocket-only mode");
            }

            if (running) {
                throw exceptions::CppJsLibException("The Server is already running");
            }

            no_websocket = true;
            websocket_only = false;

            // Check if the ports are occupied, if enabled
            if (check_ports) {
                int _err = 0;
                if (util::port_is_in_use(host.c_str(), port, _err)) {
                    err("port " + std::to_string(port) + " is already in use");
                    return false;
                } else if (_err != 0) {
                    err("port_is_in_use finished with code " + std::to_string(_err));
                }
            }

            log("Starting web server");
            nlohmann::json init_ws_json;
            init_ws_json["ws"] = "false";
            addInitHandlers(init_ws_json.dump());

            webServer->Get("/CppJsLib.js", CppJsLibJsHandler);

            // Start SSE listeners
            // Source: https://github.com/yhirose/cpp-httplib/blob/master/example/sse.cc
            addSseListener();

            running = true;
            startWebServer(port, host, block);

            return running;
        }

        inline bool startBlocking(uint16_t port, const std::string &host = localhost, uint16_t websocketPort = 0,
                                  bool block = true) {
            if (websocket_only) {
                throw exceptions::CppJsLibException("The Server is already started in websocket-only mode");
            }

            if (running) {
                throw exceptions::CppJsLibException("The Server is already running");
            }

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
            if (port == 0) {
                return startNoWeb(websocketPort, host, true);
            }

            if (websocketPort == 0) {
                return startNoWebSocket(port, host, block);
            }

            if (check_ports) {
                int wsErr = 0;
                if (util::port_is_in_use(host.c_str(), websocketPort, wsErr)) {
                    err("port " + std::to_string(websocketPort) + " is already in use");
                    return false;
                } else if (wsErr != 0) {
                    err("port_is_in_use finished with code " + std::to_string(wsErr));
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
                    err("port " + std::to_string(port) + " is already in use");
                    return false;
                } else if (_err != 0) {
                    err("port_is_in_use finished with code " + std::to_string(_err));
                }
            }

            log("Starting web server");
            nlohmann::json init_ws_json;
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
            init_ws_json["ws"] = true;
            init_ws_json["host"] = host;
            init_ws_json["port"] = websocketPort;
#   ifdef CPPJSLIB_ENABLE_HTTPS
            if (ssl) {
                init_ws_json["tls"] = true;
                if (fallback_plain) {
                    init_ws_json["fallback_plain"] = true;
                    init_ws_json["fallback_plain_port"] = fallback_plain;
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

            addInitHandlers(init_ws_json.dump());
            webServer->Get("/CppJsLib.js", CppJsLibJsHandler);

            // Start SSE listeners
            // Source: https://github.com/yhirose/cpp-httplib/blob/master/example/sse.cc
#ifndef CPPJSLIB_ENABLE_WEBSOCKET
            addSseListeners();
#endif //CPPJSLIB_ENABLE_WEBSOCKET

            running = true;
            bool wsRunning = true;

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
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
                        wsRunning && util::startNoWeb_f(websocketFallbackServer, host, fallback_plain_port, false, err, log,
                                                        [this](const std::string &msg) {
                                                            return this->handleMessages(msg);
                                                        });
            }
#   else
            log("Starting websocket server");
            wsRunning = util::startNoWeb_f(websocketServer, host, websocketPort, false, err, log,
                                           [this](const std::string &msg) {
                                               return this->handleMessages(msg);
                                           });
#   endif //CPPJSLIB_ENABLE_HTTPS
#endif //CPPJSLIB_ENABLE_WEBSOCKET

            startWebServer(port, host, block);

            return running && wsRunning;
        }

        template<class R, class... Args>
        inline void exportFunction(const std::function<R(Args...)> &func, const std::string &name) {
            initMap.insert(std::pair<std::string, size_t>(name, sizeof...(Args)));
            callFuncFromJs(name, [&func, this](const nlohmann::json &json) {
                log("Body: " + json.dump());
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

        template<class R, class... Args>
        inline void exportFunction(R (&func)(Args...), const std::string &name) {
            initMap.insert(std::pair<std::string, size_t>(name, sizeof...(Args)));
            callFuncFromJs(name, [&func, this](const nlohmann::json &json) {
                log("Body: " + json.dump());
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

        template<class R, class...Args>
        inline void importFunction(std::function<R(Args...)> &func, const std::string &name) {
            func = [this, name](Args...args) {
                nlohmann::json json = argsToJson(args...);

                std::promise<nlohmann::json> promise;
                std::future<nlohmann::json> future = promise.get_future();
                callJavascriptFunction(json, name, promise);
                future.wait();

                if constexpr (std::negation_v<std::is_same<R, void>>) {
                    return future.get().get<R>();
                } else {
                    future.get();
                }
            };
        }

        template<class R, class...Args>
        inline void importFunction(std::function<std::promise<R>(Args...)> &func, const std::string &name) {
            std::function < R(Args...) > imported;
            this->importFunction(imported, name);

            func = [imported](Args...args) {
                std::promise<R> promise;

                // Wait for the function to be resolved in a different thread
                std::thread([&] {
                    if constexpr (std::is_same_v<R, void>) {
                        imported(args...);
                        promise.set_value();
                    } else {
                        R res = imported(args...);
                        promise.set_value(res);
                    }
                }).detach();

                return promise;
            };
        };

        CPPJSLIB_NODISCARD inline bool isRunning() const {
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

        void stopNonBlocking() {
            if (isRunning()) {
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
                if (!websocket_only) {
                    log("Stopping web server");
                    webServer->stop();
                }
//#   endif //CPPJSLIB_ENABLE_HTTPS

                log("Stopping websocket server");
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
                        log("Stopping websocket plain fallback server");
                        websocketFallbackServer->stop_listening();
                        websocketFallbackServer->stop();
                    }
#   else
                    websocketServer->stop_listening();
                    websocketServer->stop();
#   endif //CPPJSLIB_ENABLE_HTTPS
                } catch (...) {
                    err("Could not close websocket server(s)");
                }
#else
                webServer->stop();
#endif //CPPJSLIB_ENABLE_WEBSOCKET
            }
        }

        std::promise<void> stop() {
            std::promise<void> promise;
            std::thread([&promise, this] {
                stopNonBlocking();

                while (isRunning()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                }

                promise.set_value();
            }).detach();

            return promise;
        }

        inline void setLogger(std::function<void(std::string)> fn) {
            log = std::move(fn);
        }

        inline void setError(std::function<void(std::string)> fn) {
            err = std::move(fn);
        }

        CPPJSLIB_NODISCARD inline std::shared_ptr<httplib::Server> getHttpServer() const {
            return webServer;
        }

        CPPJSLIB_NODISCARD inline std::shared_ptr<websocket_type> getWebsocketServer() const {
            return websocketServer;
        }

        CPPJSLIB_NODISCARD inline std::shared_ptr<websocket_ssl_type> getWebsocketTLSServer() const {
            return websocketTLSServer;
        }

        CPPJSLIB_NODISCARD inline std::shared_ptr<websocket_fallback_type> getWebsocketFallbackServer() const {
            return websocketFallbackServer;
        }

        inline ~Server() {
            stopNonBlocking();

            while (isRunning()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
        }

        /**
         * Whether to check if ports are already in use
         * when the servers are started
         */
        bool check_ports;
    private:
        using PostHandler = std::function<nlohmann::json(nlohmann::json req_body)>;

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

        template<std::size_t... S, class R, class... Args>
        static nlohmann::json
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

        template<class...Args>
        static nlohmann::json argsToJson(Args...args) {
            nlohmann::json json;
            [[maybe_unused]] volatile auto x = {(json.push_back(args), 0)...};

            return json;
        };

        static void CppJsLibJsHandler(const httplib::Request &req, httplib::Response &res) {
            std::ifstream inFile;
            inFile.open("CppJsLibJs/CppJsLib.js");
            if (!inFile.is_open()) {
                res.status = 404;
                return;
            }

            std::stringstream strStream;
            strStream << inFile.rdbuf();
            std::string str = strStream.str();
            inFile.clear();
            inFile.close();
            strStream.clear();

            res.set_content(str, "text/javascript");
        }

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

            log("Parsing message " + msg);

            nlohmann::json json = nlohmann::json::parse(msg);
            if (json.find("header") == json.end()) {
                throw exceptions::CppJsLibException("json structure did not contain a header");
            }

            std::string header = json["header"];

            if (header == "ping") {
                return "pong";
            } else if (header == "init") {
                if (websocket_only) {
                    if (json.find("callback") == json.end()) {
                        throw exceptions::CppJsLibException("json structure had no callback");
                    }

                    nlohmann::json callback;
                    callback["callback"] = json["callback"];
                    callback["data"] = initString;
                    std::string payload = callback.dump();
                    log("Sending callback: " + payload);
                    return payload;
                }
            } else if (header == "callback") { // This is an answer to a previous function call
                if (json.find("data") == json.end()) {
                    throw exceptions::CppJsLibException("json structure did not contain data");
                }

                if (json.find("callback") == json.end()) {
                    throw exceptions::CppJsLibException("json structure had no callback");
                }

                try {
                    if (json["ok"]) {
                        javascriptCallbacks.at(json["callback"]).set_value(json["data"]);
                    } else {
                        javascriptCallbacks.at(json["callback"]).set_exception(
                                std::make_exception_ptr(exceptions::CppJsLibException(json["data"])));
                    }
                } catch (const std::exception &e) {
                    err("Could not set the return value: " + std::string(e.what()));
                }

                try {
                    javascriptCallbacks.erase(json["callback"]);
                } catch (const std::exception &e) {
                    err("Could not erase a callback: " + std::string(e.what()));
                }
            } else if (header == "call") {
                // Send a callback with the result of the function in the format [CALLBACK] [DATA]
                nlohmann::json callback;
                callback["callback"] = json["callback"];

                if (json.find("callback") == json.end()) {
                    throw exceptions::CppJsLibException("json structure had no callback");
                }

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
                    log("Calling function: " + json["func"].dump());
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

        inline void addSseListener() {
            //for (const std::string &s : sseFunctionNames) {
            const auto sseHandler = [this](const httplib::Request &, httplib::Response &res) {
                log("Client connected to server sent event");
                eventDispatcher->clientConnected();
                res.set_header("Content-Type", "text/event-stream");
                res.set_chunked_content_provider("text/event-stream", [this](uint64_t, httplib::DataSink &sink) {
                    eventDispatcher->wait_event(&sink);
                    eventDispatcher->clientDisconnected();
                    return true;
                });
            };

            //sseFunctions.insert(std::pair<std::string, std::shared_ptr<util::EventDispatcher>>(s, ed));

            std::string pattern = "/cppjslib_events";
            log("Adding SSE listen pattern: " + pattern);
            webServer->Get(pattern.c_str(), sseHandler);
            //}
            //sseFunctionNames.clear();
        }

        inline void addInitHandlers(const std::string &init_ws_string) {
            nlohmann::json initList;
            for (const auto &p: initMap) {
                initList[p.first] = p.second;
            }
            initMap.clear();

            initString = initList.dump();
            const auto initHandler = [this](const httplib::Request &req, httplib::Response &res) {
                res.set_content(initString, "text/plain");
            };

            const auto init_ws_handler = [init_ws_string](const httplib::Request &req, httplib::Response &res) {
                res.set_content(init_ws_string, "text/plain");
            };

            webServer->Get("/init", initHandler);
            webServer->Get("/init_ws", init_ws_handler);
        }

        inline void startWebServer(uint16_t port, const std::string &host, bool block) {
            std::function < void() > func;
            func = [&host, port, this]() {
                if (!webServer->listen(host.c_str(), port)) {
                    err("Could not start web server");
                    running = false;
                }

                stopped = true;
            };

            if (!block) {
                log("Starting web server in non-blocking mode");
                std::thread t(func);
                t.detach();

                // Sleep for one second, so the servers can fail
                log("Sleeping for a short while");
                std::this_thread::sleep_for(std::chrono::seconds(1));
            } else {
                log("Starting web server in blocking mode");
                func();
            }
        }

        inline void callJavascriptFunction(const nlohmann::json &args, const std::string &funcName,
                                           std::promise<nlohmann::json> &promise) {
            // Dump the list of arguments into a json string
            nlohmann::json j;
            j["header"] = "call";
            j["func"] = funcName;
            j["data"] = args;
            log("Function name: " + funcName);
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
            if (no_websocket) {
                /*if (promise) {
                    err("Cannot call a JavaScript function with a return value because the websocket server was disabled");
                    return;
                }*/

                std::string str = j.dump();
                log("Calling js function via server sent events: " + str);

                if (!eventDispatcher->isClientConnected()) {
                    throw exceptions::CppJsLibException("There is no client listening to the server sent event");
                }

                try {
                    eventDispatcher->send_event(str);
                } catch (std::exception &) {
                    err("Could not call the function via server sent events");
                }
            } else {
                // Set the message handlers if the function is non-void
                std::string callback = util::gen_random(40);
                log("Waiting for results from javascript");
                while (javascriptCallbacks.count(callback) != 0) {
                    callback = util::gen_random(40);
                }

                j["callback"] = callback;
                javascriptCallbacks.insert(std::pair<std::string, std::promise<nlohmann::json> &>(callback, promise));

                std::string str = j.dump();
                log("Calling js function via websocket: " + str);

                // Send request to all clients
                log("Sending request");
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
                        err("Could not send message");
                    }
                }

#   ifdef CPPJSLIB_ENABLE_HTTPS
                if (fallback_plain_port) {
                    log("Sending message to websocket plain fallback server");
                    for (const auto &it : *websocketFallbackConnections) {
                        try {
                            websocketFallbackServer->send(it, str, websocketpp::frame::opcode::value::text);
                        } catch (...) {
                            err("Could not send message");
                        }
                    }
                }
#   endif //CPPJSLIB_ENABLE_HTTPS
            }
#else
            std::string str = j.dump();
            log("Calling js function via server sent events: " + str);

            try {
                sseFunctions.at(funcName)->send_event(str);
            } catch (std::exception &) {
                err("Could not call the function via server sent events");
            }
#endif //CPPJSLIB_ENABLE_WEBSOCKET
        }

        inline void callFuncFromJs(const std::string &name, const PostHandler &fn) {
            websocketTargets.insert(std::pair<std::string, PostHandler>(name, fn));
        }

        const bool ssl; // Whether to use ssl
        bool websocket_only; // Whether this is websocket only
        bool no_websocket; // Whether websocket is disabled
        bool running, stopped; // Whether the servers are running or stopped
        std::string base_dir; // The web base directory
        uint16_t fallback_plain_port; // The websocket plain fallback server port
        std::string initString; // The init string. Contains all exported functions in a json array as a string.

        // The function initializer map.
        // Contains the function name as a key
        // and the number of arguments as a value.
        std::map<std::string, size_t> initMap;

        // The javascript callbacks. Used for when the js functions return values.
        // Has a random string as a key, used to identify the callback
        // and a reference to a promise to be resolved.
        std::map<std::string, std::promise<nlohmann::json> &> javascriptCallbacks;

        // The server sent events function map.
        // Contains the function name as a key and the EventDispatcher
        // used to "call" the function as a value.
        //std::map<std::string, std::shared_ptr<util::EventDispatcher>> sseFunctions;

        // The sse function names to be imported.
        // Will be used to create the correct sse listeners.
        // Just contains the function names of the functions to be imported.
        //std::vector<std::string> sseFunctionNames;

        // The websocket target functions
        std::map<std::string, PostHandler> websocketTargets;

        // The logging and error functions
        std::function<void(const std::string &)> log, err;

        // The http(s) server
        std::shared_ptr<httplib::Server> webServer;

        // The event dispatcher as an alternative to websockets
        std::shared_ptr<util::EventDispatcher> eventDispatcher;

        std::shared_ptr<websocket_type> websocketServer;
        std::shared_ptr<websocket_ssl_type> websocketTLSServer;
        std::shared_ptr<websocket_fallback_type> websocketFallbackServer;
        std::shared_ptr<websocket_con_list> websocketConnections;
        std::shared_ptr<websocket_fallback_connections_type> websocketFallbackConnections;
    };
}// namespace markusjx::CppJsLib

#endif //MARKUSJX_CPPJSLIB_HPP