//
// Created by markus on 02/03/2020.
//

#include "CppJsLib.hpp"

#include <httplib.h>
#include <json.hpp>

#include "websocket.hpp"
#include "loggingfunc.hpp"
#include "socket.hpp"

using namespace CppJsLib;

#ifdef CPPJSLIB_ENABLE_HTTPS
#   define CPPJSLIB_DISABLE_SSL_MACRO ,ssl(false), fallback_plain(false)
#else
#   define CPPJSLIB_DISABLE_SSL_MACRO
#endif //CPPJSLIB_ENABLE_HTTPS

WebGUI::WebGUI(const std::string &base_dir)
        : initMap(), voidPtrVector(), strVecVector()CPPJSLIB_DISABLE_SSL_MACRO {
    std::shared_ptr<httplib::Server> svr = std::make_shared<httplib::Server>();
    server = std::static_pointer_cast<void>(svr);

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
#   ifdef CPPJSLIB_ENABLE_HTTPS
    setPassword();
#   endif //CPPJSLIB_ENABLE_HTTPS

    std::shared_ptr<wspp::server> ws_svr = std::make_shared<wspp::server>();
    std::shared_ptr<wspp::con_list> ws_con = std::make_shared<wspp::con_list>();
    ws_connections = std::static_pointer_cast<void>(ws_con);
    initWebsocketServer(ws_svr, ws_con);

    ws_server = std::static_pointer_cast<void>(ws_svr);
#endif //CPPJSLIB_ENABLE_WEBSOCKET

    check_ports = true;
    running = false;
    stopped = false;
    this->setLogger(loggingF);

    this->setError(errorF);

    char *base = strdup(base_dir.c_str());
    pushToVoidPtrVector((void *) base);
    std::static_pointer_cast<httplib::Server>(server)->set_mount_point("/", base);
}

#ifdef CPPJSLIB_ENABLE_HTTPS

WebGUI::WebGUI(const std::string &base_dir, const std::string &cert_path,
               const std::string &private_key_path, unsigned short websocket_fallback_plain)
        : initMap(), voidPtrVector(), strVecVector(), ssl(true), fallback_plain(websocket_fallback_plain) {
    if (cert_path.empty() && private_key_path.empty()) {
        errorF("No certificate paths were given");
        return;
    }

#if defined(CPPJSLIB_ENABLE_WEBSOCKET) && defined(CPPJSLIB_ENABLE_HTTPS)
    setPassword();
#endif

    char *cert = strdup(cert_path.c_str());
    char *private_key = strdup(private_key_path.c_str());
    pushToVoidPtrVector((void *) cert);
    pushToVoidPtrVector((void *) private_key);
    std::shared_ptr<httplib::SSLServer> svr = std::make_shared<httplib::SSLServer>(cert, private_key);
    server = std::static_pointer_cast<void>(svr);

#   ifdef CPPJSLIB_ENABLE_WEBSOCKET
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
#   endif //CPPJSLIB_ENABLE_WEBSOCKET

    check_ports = true;
    running = false;
    stopped = false;
    this->setLogger(loggingF);
    this->setError(errorF);

    char *base = strdup(base_dir.c_str());
    pushToVoidPtrVector((void *) base);
    std::static_pointer_cast<httplib::SSLServer>(server)->set_mount_point("/", base);
}

#endif //CPPJSLIB_ENABLE_HTTPS

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
CPPJSLIB_EXPORT bool WebGUI::start(int port, int websocketPort, const std::string &host, bool block) {
#else

CPPJSLIB_EXPORT bool WebGUI::start(int port, const std::string &host, bool block) {
#endif //CPPJSLIB_ENABLE_WEBSOCKET

    // Check if the ports are occupied, if enabled
    if (check_ports) {
        int err = 0;
        if (port_is_in_use(host.c_str(), port, err)) {
            errorF("[CppJsLib] port " + std::to_string(port) + " is already in use");
            return false;
        } else if (err != 0) {
            errorF("[CppJsLib] port_is_in_use finished with code " + std::to_string(err));
        }

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
        if (port_is_in_use(host.c_str(), websocketPort, err)) {
            errorF("[CppJsLib] port " + std::to_string(websocketPort) + " is already in use");
            return false;
        } else if (err != 0) {
            errorF("[CppJsLib] port_is_in_use finished with code " + std::to_string(err));
        }
#endif //CPPJSLIB_ENABLE_WEBSOCKET
    }

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
#   ifdef CPPJSLIB_ENABLE_HTTPS
    if (ssl) {
        init_ws_json["tls"] = "true";
        if (fallback_plain) {
            init_ws_json["fallback_plain"] = "true";
            init_ws_json["fallback_plain_port"] = fallback_plain;
        } else {
            init_ws_json["fallback_plain"] = "false";
        }
    } else
#   endif //CPPJSLIB_ENABLE_HTTPS
        init_ws_json["tls"] = "false";
#else
    init_ws_json["ws"] = "false";
#endif //CPPJSLIB_ENABLE_WEBSOCKET

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
    init_ws_json["host"] = host;
    init_ws_json["port"] = websocketPort;
#endif //CPPJSLIB_ENABLE_WEBSOCKET

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
#endif //CPPJSLIB_ENABLE_HTTPS
    std::static_pointer_cast<httplib::Server>(server)->Get("/init", initHandler);
    std::static_pointer_cast<httplib::Server>(server)->Get("/CppJsLib.js", CppJsLibJsHandler);
    std::static_pointer_cast<httplib::Server>(server)->Get("/init_ws", init_ws_handler);
#ifdef CPPJSLIB_ENABLE_HTTPS
    }
#endif //CPPJSLIB_ENABLE_HTTPS

    running = true;
    bool *runningPtr = &running;
    bool *stoppedPtr = &stopped;

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
    std::shared_ptr<void> _ws_server = this->ws_server;

#   ifdef CPPJSLIB_ENABLE_HTTPS
    const bool *_ssl = &ssl;

    std::thread websocketThread([_ssl, _ws_server, websocketPort] {
        if (*_ssl)
            startWebsocketServer(std::static_pointer_cast<wspp::server_tls>(_ws_server), websocketPort);
        else
#   else
            std::thread websocketThread([_ws_server, websocketPort] {
#   endif //CPPJSLIB_ENABLE_HTTPS
            startWebsocketServer(std::static_pointer_cast<wspp::server>(_ws_server), websocketPort);
    });
    websocketThread.detach();

#   ifdef CPPJSLIB_ENABLE_HTTPS
    if (fallback_plain) {
        std::shared_ptr<void> _ws_plain_server = this->ws_plain_server;

        std::thread websocketPlainThread([_ws_plain_server, websocketPort] {
            startWebsocketServer(std::static_pointer_cast<wspp::server>(_ws_plain_server), websocketPort);
        });
        websocketPlainThread.detach();
    }
#   endif //CPPJSLIB_ENABLE_HTTPS
#endif //CPPJSLIB_ENABLE_WEBSOCKET

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
#endif //CPPJSLIB_ENABLE_HTTPS
    std::shared_ptr<httplib::Server> svr = std::static_pointer_cast<httplib::Server>(server);
    func = [svr, host, port, runningPtr, stoppedPtr]() {
        if (!svr->listen(host.c_str(), port)) {
            (*runningPtr) = false;
        }

        (*stoppedPtr) = true;
    };
#ifdef CPPJSLIB_ENABLE_HTTPS
    }
#endif //CPPJSLIB_ENABLE_HTTPS

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
#endif //CPPJSLIB_ENABLE_HTTPS
    std::static_pointer_cast<httplib::Server>(server)->Post(target, f);
}

CPPJSLIB_EXPORT void WebGUI::setLogger(const std::function<void(const std::string &)> &f) {
    _loggingF = [f](const std::string &s) {
        f(s);
    };
}

CPPJSLIB_EXPORT void WebGUI::setError(const std::function<void(const std::string &)> &f) {
    _errorF = [f](const std::string &s) {
        f(s);
    };
}

#ifdef CPPJSLIB_ENABLE_WEBSOCKET

CPPJSLIB_EXPORT void WebGUI::setWebSocketOpenHandler(const std::function<void()> &handler) {
#   ifdef CPPJSLIB_ENABLE_HTTPS
    if (ssl)
        std::static_pointer_cast<wspp::server_tls>(ws_server)->set_open_handler([handler](auto hdl) {
            handler();
        });
    else
#   endif //CPPJSLIB_ENABLE_HTTPS
        std::static_pointer_cast<wspp::server>(ws_server)->set_open_handler([handler](auto hdl) {
            handler();
        });
}

CPPJSLIB_EXPORT void WebGUI::setWebSocketCloseHandler(const std::function<void()> &handler) {
#   ifdef CPPJSLIB_ENABLE_HTTPS
    if (ssl)
        std::static_pointer_cast<wspp::server_tls>(ws_server)->set_close_handler([handler](auto hdl) {
            handler();
        });
    else
#   endif //CPPJSLIB_ENABLE_HTTPS
        std::static_pointer_cast<wspp::server>(ws_server)->set_close_handler([handler](auto hdl) {
            handler();
        });
}

#endif //CPPJSLIB_ENABLE_WEBSOCKET

CPPJSLIB_EXPORT void WebGUI::log(const std::string &msg) {
    _loggingF(msg);
}

CPPJSLIB_EXPORT void WebGUI::err(const std::string &msg) {
    _errorF(msg);
}

CPPJSLIB_EXPORT void WebGUI::pushToVoidPtrVector(void *f) {
    voidPtrVector.push_back(f);
}

CPPJSLIB_EXPORT void WebGUI::pushToStrVecVector(std::vector<char *> *v) {
    strVecVector.push_back(v);
}

CPPJSLIB_EXPORT void WebGUI::insertToInitMap(char *name, char *exposedFStr) {
    initMap.insert(std::pair<char *, char *>(name, exposedFStr));
}

CPPJSLIB_EXPORT void WebGUI::set_mount_point(const char *mnt, const char *dir) {
#ifdef CPPJSLIB_ENABLE_HTTPS
    if (ssl)
        std::static_pointer_cast<httplib::SSLServer>(server)->set_mount_point(mnt, dir);
    else
#endif //CPPJSLIB_ENABLE_HTTPS
    std::static_pointer_cast<httplib::Server>(server)->set_mount_point(mnt, dir);
}

CPPJSLIB_EXPORT void WebGUI::remove_mount_point(const char *mnt) {
#ifdef CPPJSLIB_ENABLE_HTTPS
    if (ssl)
        std::static_pointer_cast<httplib::SSLServer>(server)->remove_mount_point(mnt);
    else
#endif //CPPJSLIB_ENABLE_HTTPS
    std::static_pointer_cast<httplib::Server>(server)->remove_mount_point(mnt);
}

WebGUI::~WebGUI() {
    stop(this);

    for (void *p : voidPtrVector) {
        free(p);
    }

    for (std::vector<char *> *v : strVecVector) {
        for (char *c: *v) {
            free(c);
        }
        delete v;
    }
}
