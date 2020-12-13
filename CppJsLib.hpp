#ifndef MARKUSJX_CPPJSLIB_HPP
#define MARKUSJX_CPPJSLIB_HPP

#ifdef CPPJSLIB_ENABLE_HTTPS
#define CPPHTTPLIB_OPENSSL_SUPPORT
#endif//CPPJSLIB_ENABLE_HTTPS

#include <functional>
#include <httplib.h>
#include <json.hpp>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <type_traits>

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
#include <set>
#include <websocketpp/server.hpp>
#ifdef CPPJSLIB_ENABLE_HTTPS
#include <websocketpp/config/asio.hpp>
#else
#include <websocketpp/config/asio_no_tls.hpp>
#endif//CPPJSLIB_ENABLE_HTTPS
#endif//CPPJSLIB_ENABLE_WEBSOCKET

#define expose(func) exportFunction(func, #func)

namespace markusjx::CppJsLib {
    namespace exceptions {
        class CppJsLibException : public std::exception {
        public:
            inline const char *getExceptionType() const noexcept { return exceptionType; }

            inline const char *what() const noexcept override { return message.c_str(); }

        protected:
            CppJsLibException(const char *exceptionType, const std::string &msg)
                : message(msg), exceptionType(exceptionType), std::exception() {}

        private:
            const char *exceptionType;
            const std::string message;
        };

        class ArgumentCountMismatchException : public CppJsLibException {
        public:
            ArgumentCountMismatchException(const std::string &msg)
                : CppJsLibException("ArgumentCountMismatchException", msg) {}
        };

        class InvalidArgumentsException : public CppJsLibException {
        public:
            InvalidArgumentsException(const std::string &msg)
                : CppJsLibException("InvalidArgumentsException", msg) {}
        };
    }// namespace exceptions

    namespace util {
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
        static void initWebsocketServer(std::shared_ptr<EndpointType> s,
                                        const std::shared_ptr<wspp::con_list> &list) {
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
            } catch (websocketpp::exception const &e) {
                //errorF("Could not initialize websocket server. Error: " + std::string(e.what()));
            } catch (...) {
                //errorF("An unknown exception occurred");
            }
        }

        template<typename EndpointType>
        static void
        startWebsocketServer(std::shared_ptr<EndpointType> s, const std::string &host, int port) {
            //loggingF("Starting websocket to listen on host " + host + " and port " + std::to_string(port));
            try {
                s->listen(host, std::to_string(port));
                s->start_accept();

                s->run();
            } catch (websocketpp::exception const &e) {
                //errorF("Could not start listening. Error: " + std::string(e.what()));
            } catch (...) {
                //errorF("An unknown exception occurred");
            }
        }

        template<typename Endpoint>
        void onMessage(std::shared_ptr<Endpoint> s,
                       const std::string &initString,
                       const std::map<std::string, std::function<std::string(std::string)>> &websocketTargets,
                       const std::function<void(const std::string &)> &_errorF,
                       const std::function<void(const std::string &)> &_loggingF,
                       bool websocket_only,
                       const std::map<std::string, std::vector<std::string> *> &jsFnCallbacks,
                       websocketpp::connection_hdl hdl,
                       const wspp::server::message_ptr &msg) {
            try {
                //_loggingF("Received data: " + msg->get_payload());
                // Receive data by the format [HEADER] [DATA] <[CALLBACK]>
                nlohmann::json json = nlohmann::json::parse(msg->get_payload());
                if (json.find("header") == json.end()) {
                    _errorF("json structure did not contain a header");
                    return;
                }

                std::string header = json["header"];

                if (header == "init") {
                    if (websocket_only) {
                        if (json.find("callback") == json.end()) {
                            //_errorF("json structure had no callback");
                            return;
                        }
                        nlohmann::json callback;
                        callback["callback"] = json["callback"];
                        callback["data"] = initString;
                        std::string payload = callback.dump();
                        //_loggingF("Sending callback: " + payload);
                        s->send(hdl, payload, websocketpp::frame::opcode::text);
                    }
                } else if (header == "callback") { // This is an answer to a previous function call
                    if (json.find("data") == json.end()) {
                        //_errorF("json structure did not contain data");
                        return;
                    }

                    if (json.find("callback") == json.end()) {
                        //_errorF("json structure had no callback");
                        return;
                    }

                    for (const auto &p : jsFnCallbacks) {
                        if (p.first == json["callback"]) {
                            p.second->push_back(json["data"]);
                            return;
                        }
                    }
                } else {
                    if (websocket_only) {
                        if (json.find("data") == json.end()) {
                            //_errorF("json structure did not contain data");
                            return;
                        }
                        // Prepend a slash to match the call template: /callfunc_
                        header.insert(0, 1, '/');

                        websocketTargets.

                        for (const auto &p : websocketTargets) {
                            if (p.first == header) {
                                bool res;
                                if (json.find("callback") != json.end()) {
                                    // Send a callback with the result of the function in the format [CALLBACK] [DATA]
                                    nlohmann::json callback;
                                    callback["callback"] = json["callback"];
                                    callback["data"] = p.second(json["data"], res);
                                    s->send(hdl, callback.dump(), websocketpp::frame::opcode::text);
                                } else {
                                    p.second(json["data"], res);
                                }
                                return;
                            }
                        }
                    }
                }
            } catch (websocketpp::exception const &e) {
                //_errorF("Websocket receive failed: " + std::string(e.what()));
            }
        }

        template<typename Endpoint>
        static bool startNoWeb_f(std::shared_ptr<Endpoint> ws_server,
                                 const std::string &host,
                                 int port,
                                 bool block,
                                 std::string initString,
                                 const std::map<std::string, WebGUI::PostHandler> &websocketTargets,
                                 const std::function<void(const std::string &)> &_errorF,
                                 const std::function<void(const std::string &)> &_loggingF,
                                 bool websocket_only,
                                 std::map<std::string, std::vector<std::string> *> jsFnCallbacks) {
            ws_server->set_message_handler(bind(&onMessage<Endpoint>, ws_server, initString,
                                                websocketTargets, _errorF, _loggingF,
                                                websocket_only, jsFnCallbacks,
                                                std::placeholders::_1, std::placeholders::_2));

            if (block) {
                //_loggingF("Starting websocket server in blocking mode");
                startWebsocketServer(ws_server, host, port);
            } else {
                //_loggingF("Starting websocket server in non-blocking mode");
                std::thread websocketThread([ws_server, port, host] {
                    startWebsocketServer(ws_server, host, port);
                });
                websocketThread.detach();

                std::this_thread::sleep_for(std::chrono::seconds(1));
            }

            if (ws_server->is_listening()) {
                //_loggingF("Successfully started websocket server");
            } else {
                //_errorF("Could not start websocket server");
            }

            return ws_server->is_listening();
        }
#endif//CPPJSLIB_ENABLE_WEBSOCKET
    }// namespace util


    class WebGUI {
    public:
        explicit inline WebGUI(const std::string &base_dir) : base_dir(base_dir), ssl(false) {
            webServer = std::make_shared<httplib::Server>();
            webServer->set_mount_point("/", this->base_dir.c_str());

            websocket_only = false;
            no_websocket = false;

            running = false;
            stopped = true;

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
#ifdef CPPJSLIB_ENABLE_HTTPS
            util::setPassword();
#endif//CPPJSLIB_ENABLE_HTTPS

            //loggingF("Initializing websocket server");
            websocketServer = std::make_shared<util::wspp::server>();
            websocketConnections = std::make_shared<util::wspp::con_list>();

            util::initWebsocketServer(websocketServer, websocketConnections);
#endif//CPPJSLIB_ENABLE_WEBSOCKET
        }

#ifdef CPPJSLIB_ENABLE_HTTPS
        inline WebGUI(const std::string &base_dir,
                      const std::string &cert_path,
                      const std::string &private_key_path,
                      bool fallback_plain = true) {
            if (cert_path.empty() || private_key_path.empty()) {
                throw exceptions::InvalidArgumentsException(
                        "The certificate or private key paths were empty");
            }

            websocket_only = false;
            no_websocket = false;

            webServer = std::make_shared<httplib::SSLServer>(cert_path.c_str(),
                                                             private_key_path.c_str());

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
#endif//CPPJSLIB_ENABLE_HTTPS

        template<class R, class... Args>
        inline void exportFunction(const std::function<R(Args...)> &func, const std::string &name) {
            callFuncFromJs(
                    name,
                    [&func](const std::string &body) {
                        nlohmann::json json = nlohmann::json::parse(body);
                        if (json.size() != sizeof...(Args)) {
                            std::stringstream ss;
                            ss << "The number of arguments did not match: " << json.size();
                            ss << " vs. " << sizeof...(Args);
                            throw exceptions::ArgumentCountMismatchException(ss.str());
                        }

                        auto sequence = std::index_sequence_for<Args...>{};
                        return callFuncFromJsonInput(sequence, json, func);
                    },
                    std::negation_v<std::is_same<R, void>>);
        }

        template<class R, class... Args>
        inline void exportFunction(R (*func)(Args...), const std::string &name) {
            exportFunction(std::function<R(Args...)>(func), name);
        }

        bool check_ports;

    private:
        using PostHandler = std::function<std::string(const std::string &req_body)>;

        template<std::size_t... S, class R, class... Args>
        static std::string callFuncFromJsonInput(std::index_sequence<S...>,
                                                 const nlohmann::json &j,
                                                 const std::function<R(Args...)> &fn) {
            if constexpr (std::is_same_v<R, void>) {
                fn(j[S].get<typename std::decay_t<Args>>()...);
                return std::string();
            } else {
                R res = fn(j[S].get<typename std::decay_t<Args>>()...);
                nlohmann::json json(res);

                return json.dump();
            }
        }

        inline void callFuncFromJs(const std::string &name, const PostHandler &fn, bool returns) {
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
            websocketTargets.insert(std::pair<std::string, PostHandler>(name, fn));
#endif//CPPJSLIB_ENABLE_WEBSOCKET

            if (!websocket_only) {
                const auto handler = [returns, &fn](const httplib::Request &req,
                                                    httplib::Response &res) {
                    std::string result = fn(req.body);
                    if (returns) res.set_content(result, "text/plain");
                };

                std::string target = "/callfunc_";
                target.append(name);
                webServer->Post(target.c_str(), handler);
            }
        }

        const bool ssl;
        bool websocket_only;
        bool no_websocket;
        bool running, stopped;
        std::string base_dir;

        // The websocket target functions
        std::map<std::string, PostHandler> websocketTargets;

        // The logging and error functions
        std::function<void(const std::string &)> log, err;

        // The http(s) server
        std::shared_ptr<httplib::Server> webServer;

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
        using websocket_con_list = util::wspp::con_list;
#ifdef CPPJSLIB_ENABLE_HTTPS
        using websocket_type = util::wspp::tls_server;
        using websocket_fallback_type = util::wspp::server;
        using websocket_fallback_connections_type = util::wspp::con_list;
#else
        using websocket_type = util::wspp::server;
        using websocket_fallback_type = void;
        using websocket_fallback_connections_type = void;
#endif//CPPJSLIB_ENABLE_HTTPS
#else
        using websocket_con_list = void;
        using websocket_type = void;
        using websocket_fallback_type = void;
        using websocket_fallback_connections_type = void;
#endif//CPPJSLIB_ENABLE_WEBSOCKET

        std::shared_ptr<websocket_type> websocketServer;
        std::shared_ptr<websocket_fallback_type> websocketFallbackServer;
        std::shared_ptr<websocket_con_list> websocketConnections;
        std::shared_ptr<websocket_fallback_connections_type> websocketFallbackConnections;
    };
}// namespace markusjx::CppJsLib

#endif//MARKUSJX_CPPJSLIB_HPP