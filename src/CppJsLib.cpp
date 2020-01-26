//
// Created by Markus on 11/12/2019.
//

#include "CppJsLib.hpp"

#include <json.hpp>
#include <httplib.h>
#include <thread>
#include <utility>

using namespace CppJsLib;

std::function<void(const std::string &)> loggingF = nullptr;
std::function<void(const std::string &)> errorF = nullptr;

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
#ifdef CPPJSLIB_ENABLE_HTTPS
#define CPPJSLIB_CERTS , const std::string &cert_path, const std::string &private_key_path
#else
#define CPPJSLIB_CERTS
#endif

#   include <set>
#   include <websocketpp/server.hpp>

#   ifdef CPPJSLIB_ENABLE_HTTPS

#       include <websocketpp/config/asio.hpp>

namespace wspp {
    typedef websocketpp::server<websocketpp::config::asio> server;
    typedef websocketpp::server<websocketpp::config::asio_tls> server_tls;
    typedef websocketpp::lib::shared_ptr<websocketpp::lib::asio::ssl::context> context_ptr;
}

void initWebsocketTLS(const std::shared_ptr<wspp::server_tls> &s CPPJSLIB_CERTS);

#   else
#       include <websocketpp/config/asio_no_tls.hpp>
namespace wspp {
    typedef websocketpp::server<websocketpp::config::asio> server;
}
#   endif

namespace wspp {
    typedef std::set<websocketpp::connection_hdl, std::owner_less<websocketpp::connection_hdl>> con_list;
}

using websocketpp::lib::placeholders::_1;
using websocketpp::lib::placeholders::_2;
using websocketpp::lib::bind;

template<typename EndpointType>
void initWebsocketServer(std::shared_ptr<EndpointType> s, const std::shared_ptr<wspp::con_list> &list) {
    try {
        s->set_open_handler(bind([list](const websocketpp::connection_hdl &hdl) {
            list->insert(hdl);
        }, ::_1));
        s->set_close_handler(bind([list](const websocketpp::connection_hdl &hdl) {
            list->erase(hdl);
        }, ::_1));

        s->set_access_channels(websocketpp::log::alevel::all);
        s->clear_access_channels(websocketpp::log::alevel::frame_payload);

        s->init_asio();
    } catch (websocketpp::exception const &e) {
        if (errorF) errorF(e.what());
    } catch (...) {
        if (errorF) errorF("An unknown exception occurred");
    }
}

template<typename EndpointType>
void startWebsocketServer(std::shared_ptr<EndpointType> s, int port) {
    s->listen(port);
    s->start_accept();

    s->run();
}

std::string password;
#ifdef CPPJSLIB_ENABLE_HTTPS
enum tls_mode {
    MOZILLA_INTERMEDIATE = 1,
    MOZILLA_MODERN = 2
};

std::string get_password() {
    return password;
}

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

void on_http(wspp::server_tls *s, websocketpp::connection_hdl hdl) {
    wspp::server_tls::connection_ptr con = s->get_con_from_hdl(std::move(hdl));

    con->set_body("Hello World!");
    con->set_status(websocketpp::http::status_code::ok);
}

wspp::context_ptr on_tls_init(tls_mode mode, const websocketpp::connection_hdl &hdl CPPJSLIB_CERTS) {
    namespace asio = websocketpp::lib::asio;

    if (loggingF)
        loggingF(
                std::string("using TLS mode: ") + (mode == MOZILLA_MODERN ? "Mozilla Modern" : "Mozilla Intermediate"));
    wspp::context_ptr ctx = websocketpp::lib::make_shared<asio::ssl::context>(asio::ssl::context::sslv23);

    try {
        if (mode == MOZILLA_MODERN) {
            // Modern disables TLSv1
            ctx->set_options(asio::ssl::context::default_workarounds |
                             asio::ssl::context::no_sslv2 |
                             asio::ssl::context::no_sslv3 |
                             asio::ssl::context::no_tlsv1 |
                             asio::ssl::context::single_dh_use);
        } else {
            ctx->set_options(asio::ssl::context::default_workarounds |
                             asio::ssl::context::no_sslv2 |
                             asio::ssl::context::no_sslv3 |
                             asio::ssl::context::single_dh_use);
        }
        ctx->set_password_callback(bind(&get_password));
        ctx->use_certificate_chain_file(cert_path);
        ctx->use_private_key_file(private_key_path, boost::asio::ssl::context::pem);

        std::string ciphers;

        if (mode == MOZILLA_MODERN) {
            ciphers = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK";
        } else {
            ciphers = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA";
        }

        if (SSL_CTX_set_cipher_list(ctx->native_handle(), ciphers.c_str()) != 1) {
            if (errorF) errorF("Error setting cipher list");
        }
    } catch (std::exception &e) {
        if (errorF) errorF(std::string("Exception: ") + e.what());
    }
    return ctx;
}

void initWebsocketTLS(const std::shared_ptr<wspp::server_tls> &s CPPJSLIB_CERTS) {
    try {
        std::function < wspp::context_ptr(tls_mode, websocketpp::connection_hdl) >
        on_tls = [cert_path, private_key_path](tls_mode mode, const websocketpp::connection_hdl &hdl) {
            return on_tls_init(mode, hdl, cert_path, private_key_path);
        };

        s->set_http_handler(bind(&on_http, s.get(), ::_1));
        s->set_tls_init_handler(bind(on_tls, MOZILLA_INTERMEDIATE, ::_1));
    } catch (websocketpp::exception const &e) {
        if (errorF) errorF(e.what());
    } catch (...) {
        if (errorF) errorF("An unknown exception occurred");
    }
}

#endif

#undef CPPJSLIB_CERTS
#endif

#ifdef CPPJSLIB_ENABLE_HTTPS
#   define CPPJSLIB_DISABLE_SSL_MACRO ,ssl(false), fallback_plain(false)
#else
#   define CPPJSLIB_DISABLE_SSL_MACRO
#endif

// WebGUI class -------------------------------------------------------------------------
CPPJSLIB_EXPORT WebGUI::WebGUI(const std::string &base_dir)
        : initMap(), funcVector(), jsFuncVector()CPPJSLIB_DISABLE_SSL_MACRO {
    std::shared_ptr<httplib::Server> svr = std::make_shared<httplib::Server>();
    server = std::static_pointer_cast<void>(svr);

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
#ifdef CPPJSLIB_ENABLE_HTTPS
    setPassword();
#endif

    std::shared_ptr<wspp::server> ws_svr = std::make_shared<wspp::server>();
    std::shared_ptr<wspp::con_list> ws_con = std::make_shared<wspp::con_list>();
    ws_connections = std::static_pointer_cast<void>(ws_con);
    initWebsocketServer(ws_svr, ws_con);

    ws_server = std::static_pointer_cast<void>(ws_svr);
#endif

    running = false;
    stopped = false;
    if (loggingF)
        _loggingF = std::move(loggingF);
    else
        _loggingF = [](const std::string &) {};

    if (errorF)
        _errorF = std::move(loggingF);
    else
        _errorF = [](const std::string &) {};

    std::static_pointer_cast<httplib::Server>(server)->set_base_dir(base_dir.c_str());
}

#ifdef CPPJSLIB_ENABLE_HTTPS

CPPJSLIB_EXPORT WebGUI::WebGUI(const std::string &base_dir, const std::string &cert_path,
                               const std::string &private_key_path, unsigned short websocket_fallback_plain)
        : initMap(), funcVector(), jsFuncVector(), ssl(true), fallback_plain(websocket_fallback_plain) {
    if (cert_path.empty() && private_key_path.empty()) {
        errorF("No certificate paths were given");
        return;
    }

    setPassword();

    std::shared_ptr<httplib::SSLServer> svr = std::make_shared<httplib::SSLServer>(cert_path.c_str(),
                                                                                   private_key_path.c_str());
    server = std::static_pointer_cast<void>(svr);

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
    std::shared_ptr<wspp::con_list> ws_con = std::make_shared<wspp::con_list>();
    ws_connections = std::static_pointer_cast<void>(ws_con);

    std::shared_ptr<wspp::server_tls> ws_svr = std::make_shared<wspp::server_tls>();
    initWebsocketTLS(ws_svr, cert_path, private_key_path);
    initWebsocketServer(ws_svr, ws_con);
    ws_server = std::static_pointer_cast<void>(ws_svr);

    if (fallback_plain) {
        std::shared_ptr<wspp::server> ws_plain_svr = std::make_shared<wspp::server>();
        std::shared_ptr<wspp::con_list> ws_plain_con = std::make_shared<wspp::con_list>();
        initWebsocketServer(ws_plain_svr, ws_plain_con);

        ws_plain_connections = std::static_pointer_cast<void>(ws_plain_con);
        ws_plain_server = std::static_pointer_cast<void>(ws_plain_svr);
    }
#endif

    running = false;
    stopped = false;
    if (loggingF)
        _loggingF = std::move(loggingF);
    else
        _loggingF = [](const std::string &) {};

    if (errorF)
        _errorF = std::move(loggingF);
    else
        _errorF = [](const std::string &) {};

    std::static_pointer_cast<httplib::SSLServer>(server)->set_base_dir(base_dir.c_str());
}

#endif

CPPJSLIB_EXPORT bool WebGUI::start(int port, CPPJSLIB_WS_PORT const std::string &host, bool block) {
    _loggingF("[CppJsLib] Starting web server");
    auto CppJsLibJsHandler = [](const httplib::Request &req, httplib::Response &res) {
        std::ifstream inFile;
        inFile.open("CppJsLibJs/CppJsLib.js");

        std::stringstream strStream;
        strStream << inFile.rdbuf();
        std::string str = strStream.str();
        inFile.clear();
        inFile.close();
        strStream.clear();

        res.set_content(str, "text/javascript");
        str.clear();
    };

    nlohmann::json initList;
    for (std::pair<char *, char *> p: initMap) {
        initList[p.first] = p.second;
        free(p.first);
        free(p.second);
    }
    std::map<char *, char *>().swap(initMap);

    std::string serialized_string = initList.dump();
    auto initHandler = [serialized_string](const httplib::Request &req, httplib::Response &res) {
        res.set_content(serialized_string, "text/plain");
    };

    nlohmann::json init_ws_json;
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
    init_ws_json["ws"] = "true";
#ifdef CPPJSLIB_ENABLE_HTTPS
    if (ssl) {
        init_ws_json["tls"] = "true";
        if (fallback_plain) {
            init_ws_json["fallback_plain"] = "true";
            init_ws_json["fallback_plain_port"] = fallback_plain;
        } else {
            init_ws_json["fallback_plain"] = "false";
        }
    } else
#endif
        init_ws_json["tls"] = "false";
#else
    init_ws_json["ws"] = "false";
#endif

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
    init_ws_json["host"] = host;
    init_ws_json["port"] = websocketPort;
#endif

    std::string init_ws_string = init_ws_json.dump();

    auto init_ws_handler = [init_ws_string](const httplib::Request &req, httplib::Response &res) {
        res.set_content(init_ws_string, "test/plain");
    };

#ifdef CPPJSLIB_ENABLE_HTTPS
    if (ssl) {
        std::static_pointer_cast<httplib::SSLServer>(server)->Get("/CppJsLib.js", CppJsLibJsHandler);
        std::static_pointer_cast<httplib::SSLServer>(server)->Get("/init", initHandler);
        std::static_pointer_cast<httplib::SSLServer>(server)->Get("/init_ws", init_ws_handler);
    } else {
#endif
        std::static_pointer_cast<httplib::Server>(server)->Get("/init", initHandler);
        std::static_pointer_cast<httplib::Server>(server)->Get("/CppJsLib.js", CppJsLibJsHandler);
        std::static_pointer_cast<httplib::Server>(server)->Get("/init_ws", init_ws_handler);
#ifdef CPPJSLIB_ENABLE_HTTPS
    }
#endif

    running = true;
    bool *runningPtr = &running;
    bool *stoppedPtr = &stopped;

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
#   ifdef CPPJSLIB_ENABLE_HTTPS
    const bool *_ssl = &ssl;
#   else
    bool ssl_ = false;
    const bool *_ssl = &ssl_;
#   endif
    std::shared_ptr<void> _ws_server = this->ws_server;

    std::thread websocketThread([_ssl, _ws_server, websocketPort] {
#   ifdef CPPJSLIB_ENABLE_HTTPS
        if (*_ssl)
            startWebsocketServer(std::static_pointer_cast<wspp::server_tls>(_ws_server), websocketPort);
        else
#   endif
            startWebsocketServer(std::static_pointer_cast<wspp::server>(_ws_server), websocketPort);
    });
    websocketThread.detach();

#ifdef CPPJSLIB_ENABLE_HTTPS
    if (fallback_plain) {
        std::shared_ptr<void> _ws_plain_server = this->ws_plain_server;

        std::thread websocketPlainThread([_ws_plain_server, websocketPort] {
            startWebsocketServer(std::static_pointer_cast<wspp::server>(_ws_plain_server), websocketPort);
        });
        websocketPlainThread.detach();
    }
#endif
#endif

    std::function < void() > func;
#ifdef CPPJSLIB_ENABLE_HTTPS
    if (ssl) {
        std::shared_ptr<httplib::SSLServer> svr = std::static_pointer_cast<httplib::SSLServer>(server);
        func = [svr, host, port, runningPtr, stoppedPtr]() {
            if (!svr->listen(host.c_str(), port)) {
                (*runningPtr) = false;
            }

            (*stoppedPtr) = true;
        };
    } else {
#endif
        std::shared_ptr<httplib::Server> svr = std::static_pointer_cast<httplib::Server>(server);
        func = [svr, host, port, runningPtr, stoppedPtr]() {
            if (!svr->listen(host.c_str(), port)) {
                (*runningPtr) = false;
            }

            (*stoppedPtr) = true;
        };
#ifdef CPPJSLIB_ENABLE_HTTPS
    }
#endif

    if (!block) {
        _loggingF("[CppJsLib] Starting web server in non-blocking mode");
        std::thread t(func);
        t.detach();
    } else {
        _loggingF("[CppJsLib] Starting web server in blocking mode");
        func();
    }

    return running;
}

CPPJSLIB_EXPORT void WebGUI::callFromPost(const char *target, const PostHandler &handler) {
    auto f = [handler](const httplib::Request &req, httplib::Response &res) {
        std::string result = handler(req.body);
        if (!result.empty()) {
            res.set_content(result, "text/plain");
        }
    };

#ifdef CPPJSLIB_ENABLE_HTTPS
    if (ssl)
        std::static_pointer_cast<httplib::SSLServer>(server)->Post(target, f);
    else
#endif
        std::static_pointer_cast<httplib::Server>(server)->Post(target, f);
}

CPPJSLIB_EXPORT void WebGUI::setLogger(std::function<void(const std::string &)> loggingFunction) {
    _loggingF = std::move(loggingFunction);
}

CPPJSLIB_EXPORT void WebGUI::setError(std::function<void(const std::string &)> errorFunction) {
    _errorF = std::move(errorFunction);
}

CPPJSLIB_EXPORT WebGUI::~WebGUI() {
    stop(this);

    for (void *p : funcVector) {
        delete static_cast<ExposedFunction<void()> *>(p);
    }

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
    for (void *p : jsFuncVector) {
        delete static_cast<JsFunction<void()> *>(p);
    }
#endif
    //Clear the vector and release the memory. Source: https://stackoverflow.com/a/10465032
    std::vector<void *>().swap(funcVector);
    std::vector<void *>().swap(jsFuncVector);
}

// End of WebGUI class ------------------------------------------------------------------

CPPJSLIB_EXPORT bool CppJsLib::stop(WebGUI *webGui, bool block, int waitMaxSeconds) {
    if (webGui->running) {
#ifdef CPPJSLIB_ENABLE_HTTPS
        if (webGui->ssl)
            webGui->getHttpsServer()->stop();
        else
#endif
            webGui->getHttpServer()->stop();
        if (waitMaxSeconds != CPPJSLIB_DURATION_INFINITE && block) {
            waitMaxSeconds = waitMaxSeconds * 100;
            int waited = 0;
            while (!webGui->stopped && waited < waitMaxSeconds) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                waited++;
            }

            if (!webGui->stopped && errorF) {
                errorF("Timed out during socket close");
            }
        } else if (block) {
            while (!webGui->stopped) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }
    }
    webGui->running = !webGui->stopped;

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
#ifdef CPPJSLIB_ENABLE_HTTPS
    if (webGui->ssl) {
        webGui->getTLSWebServer()->stop();
        if (webGui->fallback_plain)
            webGui->getWebServer()->stop();
    } else
#endif
        webGui->getWebServer()->stop();
#endif

    return webGui->stopped;
}

CPPJSLIB_EXPORT std::string *CppJsLib::parseJSONInput(int *size, const std::string &args) {
    using json = nlohmann::json;
    json j = json::parse(json::parse(args)["args"].dump());
    int s = 0;
    for (auto &it : j) s++;
    *size = s;
    auto *argArr = new std::string[s];
    int i = 0;
    for (auto &it : j) {
        argArr[i] = it.dump();
        i++;
    }

    return argArr;
}

CPPJSLIB_EXPORT std::string CppJsLib::stringArrayToJSON(std::vector<std::string> *v) {
    nlohmann::json json(*v);
    return json.dump();
}

CPPJSLIB_EXPORT std::string CppJsLib::stringToJSON(std::string s) {
    nlohmann::json json(s);
    return json.dump();
}

CPPJSLIB_EXPORT std::string *CppJsLib::createStringArrayFromJSON(int *size, const std::string &data) {
    nlohmann::json j = nlohmann::json::parse(data);
    int s = 0;
    for (auto &it : j) s++;
    *size = s;
    auto *ret = new std::string[s];
    int i = 0;
    for (auto &it : j) {
        ret[i] = it.dump();
        i++;
    }

    return ret;
}

#ifdef CPPJSLIB_ENABLE_WEBSOCKET

CPPJSLIB_EXPORT void
CppJsLib::callJsFunc(const std::shared_ptr<WebGUI>& wGui, std::vector<std::string> *argV, const char *funcName,
                     std::vector<char *> *results, int wait) {
    wGui->call_jsFn(argV, funcName, results, wait);
}

template<typename EndpointType>
void empty_on_message(EndpointType *, const websocketpp::connection_hdl &, typename EndpointType::message_ptr) {}

CPPJSLIB_EXPORT void
WebGUI::call_jsFn(std::vector<std::string> *argV, const char *funcName, std::vector<char *> *results, int wait) {
    // Dump the list of arguments into a json string
    nlohmann::json j;
    for (std::string s: *argV) {
        j[funcName].push_back(s);
    }

    std::string str = j.dump();

    std::shared_ptr<wspp::con_list> list = std::static_pointer_cast<wspp::con_list>(ws_connections);

    // Set the message handlers if the function is non-void
    if (results) {
#ifdef CPPJSLIB_ENABLE_HTTPS
        if (ssl) {
            std::shared_ptr<wspp::server_tls> ws_svr = std::static_pointer_cast<wspp::server_tls>(ws_server);
            ws_svr->set_message_handler(bind([results](wspp::server_tls *s, const websocketpp::connection_hdl &hdl,
                                                       const wspp::server_tls::message_ptr &msg) {
                results->push_back(strdup(msg->get_payload().c_str()));
            }, ws_svr.get(), ::_1, ::_2));
            if (fallback_plain) {
                std::shared_ptr<wspp::server> ws_plain_svr = std::static_pointer_cast<wspp::server>(ws_plain_server);
                ws_plain_svr->set_message_handler(
                        bind([results](wspp::server *s, const websocketpp::connection_hdl &hdl,
                                       const wspp::server_tls::message_ptr &msg) {
                            results->push_back(strdup(msg->get_payload().c_str()));
                        }, ws_plain_svr.get(), ::_1, ::_2));
            }
        } else {
#endif
            std::shared_ptr<wspp::server> ws_svr = std::static_pointer_cast<wspp::server>(ws_server);
            ws_svr->set_message_handler(bind([results](wspp::server *s, const websocketpp::connection_hdl &hdl,
                                                       const wspp::server::message_ptr &msg) {
                results->push_back(strdup(msg->get_payload().c_str()));
            }, ws_svr.get(), ::_1, ::_2));
#ifdef CPPJSLIB_ENABLE_HTTPS
        }
#endif
    }

    // Send request to all clients
    for (const auto &it : *list) {
#ifdef CPPJSLIB_ENABLE_HTTPS
        if (ssl) {
            std::static_pointer_cast<wspp::server_tls>(ws_server)->send(it, str,
                                                                        websocketpp::frame::opcode::value::text);
        } else
#endif
            std::static_pointer_cast<wspp::server>(ws_server)->send(it, str, websocketpp::frame::opcode::value::text);
    }

#ifdef CPPJSLIB_ENABLE_HTTPS
    if (fallback_plain) {
        std::shared_ptr<wspp::con_list> plain_list = std::static_pointer_cast<wspp::con_list>(ws_plain_connections);
        for (const auto &it : *plain_list) {
            std::static_pointer_cast<wspp::server>(ws_plain_server)->send(it, str,
                                                                          websocketpp::frame::opcode::value::text);
        }
    }
#endif

    if (results) {
        // Wait for the results to come in
        if (wait != -1) wait *= 100;
        unsigned int counter = 0;
        while (results->size() < list->size() && counter < wait) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            if (wait != -1) counter++;
        }
    }

    // Remove the message handler
#ifdef CPPJSLIB_ENABLE_HTTPS
    if (ssl) {
        std::shared_ptr<wspp::server_tls> ws_svr = std::static_pointer_cast<wspp::server_tls>(ws_server);
        ws_svr->set_message_handler(bind(&empty_on_message<wspp::server_tls>, ws_svr.get(), ::_1, ::_2));
        if (fallback_plain) {
            std::shared_ptr<wspp::server> ws_plain_svr = std::static_pointer_cast<wspp::server>(ws_plain_server);
            ws_plain_svr->set_message_handler(bind(&empty_on_message<wspp::server>, ws_plain_svr.get(), ::_1, ::_2));
        }
    } else {
#endif
        std::shared_ptr<wspp::server> ws_svr = std::static_pointer_cast<wspp::server>(ws_server);
        ws_svr->set_message_handler(bind(&empty_on_message<wspp::server>, ws_svr.get(), ::_1, ::_2));
#ifdef CPPJSLIB_ENABLE_HTTPS
    }
#endif
}

#endif

CPPJSLIB_EXPORT void CppJsLib::setLogger(std::function<void(const std::string &)> f) {
    loggingF = std::move(f);
}

CPPJSLIB_EXPORT void CppJsLib::setError(std::function<void(const std::string &)> f) {
    errorF = std::move(f);
}

