/*
 * WebGui.cpp
 * Defines the functions for the WebGUI class
 *
 * Licensed under the MIT License
 *
 * Copyright (c) 2020 MarkusJx
 *
 * The full license including third-party licenses is available at https://github.com/MarkusJx/CppJsLib/blob/master/LICENSE
 */
#include "CppJsLib.hpp"

#include <httplib.h>
#include <json.hpp>
#include <utility>

#include "websocket.hpp"
#include "socket.hpp"
#include "EventDispatcher.hpp"

using namespace CppJsLib;

#ifdef CPPJSLIB_ENABLE_HTTPS
#   define CPPJSLIB_DISABLE_SSL_MACRO ,ssl(false), fallback_plain(false)
#else
#   define CPPJSLIB_DISABLE_SSL_MACRO
#endif //CPPJSLIB_ENABLE_HTTPS

#if defined(CPPJSLIB_BUILD_LIB) || !defined (CPPJSLIB_STATIC_DEFINE)

#ifdef CPPJSLIB_ENABLE_HTTPS

CPPJSLIB_EXPORT WebGUI *WebGUI::create(const std::string &base_dir, const std::string &cert_path,
                                       const std::string &private_key_path,
                                       unsigned short websocket_plain_fallback_port) {
    return new WebGUI(base_dir, cert_path, private_key_path, websocket_plain_fallback_port);
}

#endif

CPPJSLIB_EXPORT WebGUI *WebGUI::create(const std::string &base_dir) {
    return new CppJsLib::WebGUI(base_dir);
}

CPPJSLIB_EXPORT void WebGUI::deleteInstance(WebGUI *webGui) {
    delete webGui;
}

#endif //CPPJSLIB_BUILD_LIB

WebGUI::WebGUI(const std::string &base_dir)
        : initMap(), voidPtrVector(), strVecVector(), websocketTargets(), jsFnCallbacks(), sseVec(), sseEventMap()
          CPPJSLIB_DISABLE_SSL_MACRO {
    std::shared_ptr<httplib::Server> svr = std::make_shared<httplib::Server>();
    server = std::static_pointer_cast<void>(svr);

    websocket_only = false;
    no_websocket = false;

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
#   ifdef CPPJSLIB_ENABLE_HTTPS
    setPassword();
#   endif //CPPJSLIB_ENABLE_HTTPS

    loggingF("Initializing websocket server");
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
        : initMap(), voidPtrVector(), strVecVector(), ssl(true), fallback_plain(websocket_fallback_plain),
          websocketTargets(), jsFnCallbacks(), sseVec(), sseEventMap() {
    if (cert_path.empty() && private_key_path.empty()) {
        errorF("No certificate paths were given");
        return;
    }

    websocket_only = false;
    no_websocket = false;

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

    loggingF("Initializing tls websocket server");
    std::shared_ptr<wspp::server_tls> ws_svr = std::make_shared<wspp::server_tls>();
    initWebsocketTLS(ws_svr, cert_path, private_key_path);
    initWebsocketServer(ws_svr, ws_con);
    ws_server = std::static_pointer_cast<void>(ws_svr);

    if (fallback_plain) {
        loggingF("Initializing websocket plain fallback server");
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

template<typename Endpoint>
void onMessage(std::shared_ptr<Endpoint> s, std::string initString,
               const std::map<std::string, WebGUI::PostHandler> &websocketTargets,
               const std::function<void(const std::string &)> &_errorF,
               const std::function<void(const std::string &)> &_loggingF, bool websocket_only,
               const std::map<std::string, std::vector<std::string> *> &jsFnCallbacks,
               websocketpp::connection_hdl hdl, const wspp::server::message_ptr &msg) {
    try {
        _loggingF("Received data: " + msg->get_payload());
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
                    _errorF("json structure had no callback");
                    return;
                }
                nlohmann::json callback;
                callback["callback"] = json["callback"];
                callback["data"] = initString;
                std::string payload = callback.dump();
                _loggingF("Sending callback: " + payload);
                s->send(hdl, payload, websocketpp::frame::opcode::text);
            }
        } else if (header == "callback") {
            if (json.find("data") == json.end()) {
                _errorF("json structure did not contain data");
                return;
            }

            if (json.find("callback") == json.end()) {
                _errorF("json structure had no callback");
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
                    _errorF("json structure did not contain data");
                    return;
                }
                // Prepend a slash to match the call template: /callfunc_
                header.insert(0, 1, '/');

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
        _errorF("Websocket receive failed: " + std::string(e.what()));
    }
}

template<typename Endpoint>
bool
startNoWeb_f(std::shared_ptr<Endpoint> ws_server, const std::string &host, int port, bool block, std::string initString,
             const std::map<std::string, WebGUI::PostHandler> &websocketTargets,
             const std::function<void(const std::string &)> &_errorF,
             const std::function<void(const std::string &)> &_loggingF, bool websocket_only,
             std::map<std::string, std::vector<std::string> *> jsFnCallbacks) {
    ws_server->set_message_handler(
            bind(&onMessage<Endpoint>, ws_server, initString, websocketTargets, _errorF, _loggingF, websocket_only,
                 jsFnCallbacks, std::placeholders::_1, std::placeholders::_2));

    if (block) {
        _loggingF("Starting websocket server in blocking mode");
        startWebsocketServer(ws_server, host, port);
    } else {
        _loggingF("Starting websocket server in non-blocking mode");
        std::thread websocketThread([ws_server, port, host] {
            startWebsocketServer(ws_server, host, port);
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

CPPJSLIB_EXPORT bool WebGUI::startNoWeb(int port, const std::string &host, bool block) {
    log("Starting without a web server");

    if (port < 0) {
        err("Cannot start websocket server with a negative port");
        return false;
    }

    if (check_ports) {
        int err = 0;
        if (port_is_in_use("localhost", port, err)) {
            errorF("port " + std::to_string(port) + " is already in use");
            return false;
        } else if (err != 0) {
            errorF("port_is_in_use finished with code " + std::to_string(err));
        }
    }

    websocket_only = true;
    no_websocket = false;

    nlohmann::json initList;
    for (std::pair<char *, char *> p : initMap) {
        initList[p.first] = p.second;
        free(p.first);
        free(p.second);
    }
    std::map<char *, char *>().swap(initMap);

    std::string initString = initList.dump();
    log("Initializing with string: " + initString);

#   ifdef CPPJSLIB_ENABLE_HTTPS
    if (fallback_plain) {
        log("Starting websocket plain fallback server");
        startNoWeb_f(std::static_pointer_cast<wspp::server>(ws_plain_server), host, fallback_plain, false, initString,
                     websocketTargets, _errorF, _loggingF, websocket_only, jsFnCallbacks);
    }

    if (ssl) {
        log("Starting websocket tls server");
        running = startNoWeb_f(std::static_pointer_cast<wspp::server_tls>(ws_server), host, port, block, initString,
                               websocketTargets, _errorF, _loggingF, websocket_only, jsFnCallbacks);
        return running;
    } else {
        log("Starting websocket server");
        running = startNoWeb_f(std::static_pointer_cast<wspp::server>(ws_server), host, port, block, initString,
                               websocketTargets, _errorF, _loggingF, websocket_only, jsFnCallbacks);
        return running;
    }
#   else
    log("Starting websocket server");
    running = startNoWeb_f(std::static_pointer_cast<wspp::server>(ws_server), host, port, block, initString,
                           websocketTargets, _errorF, _loggingF, websocket_only, jsFnCallbacks);
    return running;
#   endif
}

CPPJSLIB_EXPORT bool WebGUI::startNoWebSocket(int port, const std::string &host, bool block) {
    log("Starting without websocket server");

    if (port < 0) {
        err("Cannot start servers with a negative port number");
        return false;
    }

    // Check if this is started or websocket-only
    if (websocket_only) {
        err("WebGUI is already started in websocket-only mode");
        return false;
    }

    if (running) {
        err("WebGUI is already running");
        return false;
    }

    no_websocket = true;
    websocket_only = false;

    // Check if the ports are occupied, if enabled
    if (check_ports) {
        int _err = 0;
        if (port_is_in_use(host.c_str(), port, _err)) {
            err("port " + std::to_string(port) + " is already in use");
            return false;
        } else if (_err != 0) {
            err("port_is_in_use finished with code " + std::to_string(_err));
        }
    }

    log("Starting web server");
    auto CppJsLibJsHandler = [this](const httplib::Request &req, httplib::Response &res) {
        std::ifstream inFile;
        inFile.open("CppJsLibJs/CppJsLib.js");
        if (!inFile.is_open()) {
            err("Could not open CppJsLibJs/CppJsLib.js");
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
    init_ws_json["ws"] = "false";

    std::string init_ws_string = init_ws_json.dump();

    auto init_ws_handler = [init_ws_string](const httplib::Request &req, httplib::Response &res) {
        res.set_content(init_ws_string, "text/plain");
    };

#ifdef CPPJSLIB_ENABLE_HTTPS
    if (ssl) {
        std::static_pointer_cast<httplib::SSLServer>(server)->Get("/CppJsLib.js", CppJsLibJsHandler);
        std::static_pointer_cast<httplib::SSLServer>(server)->Get("/init", initHandler);
        std::static_pointer_cast<httplib::SSLServer>(server)->Get("/init_ws", init_ws_handler);
    } else {
        std::static_pointer_cast<httplib::Server>(server)->Get("/init", initHandler);
        std::static_pointer_cast<httplib::Server>(server)->Get("/CppJsLib.js", CppJsLibJsHandler);
        std::static_pointer_cast<httplib::Server>(server)->Get("/init_ws", init_ws_handler);
    }
#else
    std::static_pointer_cast<httplib::Server>(server)->Get("/init", initHandler);
    std::static_pointer_cast<httplib::Server>(server)->Get("/CppJsLib.js", CppJsLibJsHandler);
    std::static_pointer_cast<httplib::Server>(server)->Get("/init_ws", init_ws_handler);
#endif //CPPJSLIB_ENABLE_HTTPS

    // Start SSE listeners
    // Source: https://github.com/yhirose/cpp-httplib/blob/master/example/sse.cc
    for (const std::string &s : sseVec) {
        auto *ed = new EventDispatcher();

        auto sseHandler = [&, ed](const httplib::Request &, httplib::Response &res) {
            log("Client connected to server sent event");
            res.set_header("Content-Type", "text/event-stream");
            res.set_chunked_content_provider("text/event-stream", [ed](uint64_t, httplib::DataSink &sink) {
                ed->wait_event(&sink);
                return true;
            });
        };

        sseEventMap.insert(std::pair<std::string, void *>(s, (void *) ed));

        std::string pattern = "/ev_";
        pattern.append(s);
        log("Adding SSE listen pattern: " + pattern);
#   ifdef CPPJSLIB_ENABLE_HTTPS
        if (ssl) {
            std::static_pointer_cast<httplib::SSLServer>(server)->Get(pattern.c_str(), sseHandler);
        } else {
            std::static_pointer_cast<httplib::Server>(server)->Get(pattern.c_str(), sseHandler);
        }
#   else
        std::static_pointer_cast<httplib::Server>(server)->Get(pattern.c_str(), sseHandler);
#   endif //CPPJSLIB_ENABLE_HTTPS
    }

    sseVec.clear();

    running = true;
    bool *runningPtr = &running;
    bool *stoppedPtr = &stopped;

    std::function < void() > func;
#ifdef CPPJSLIB_ENABLE_HTTPS
    if (ssl) {
        log("Starting ssl web server");
        std::shared_ptr<httplib::SSLServer> svr = std::static_pointer_cast<httplib::SSLServer>(server);
        func = [svr, host, port, runningPtr, stoppedPtr, this]() {
            if (!svr->listen(host.c_str(), port)) {
                err("Could not start ssl web server");
                (*runningPtr) = false;
            }

            (*stoppedPtr) = true;
        };
    } else {
        log("Starting web server");
        std::shared_ptr<httplib::Server> svr = std::static_pointer_cast<httplib::Server>(server);
        func = [svr, host, port, runningPtr, stoppedPtr, this]() {
            if (!svr->listen(host.c_str(), port)) {
                err("Could not start web server");
                (*runningPtr) = false;
            }

            (*stoppedPtr) = true;
        };
    }
#else
    std::shared_ptr<httplib::Server> svr = std::static_pointer_cast<httplib::Server>(server);
    func = [svr, host, port, runningPtr, stoppedPtr, this]() {
        if (!svr->listen(host.c_str(), port)) {
            err("Could not start web server");
            (*runningPtr) = false;
        }

        (*stoppedPtr) = true;
    };
#endif //CPPJSLIB_ENABLE_HTTPS

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

    return running;
}

CPPJSLIB_MAYBE_UNUSED CPPJSLIB_EXPORT bool WebGUI::start(int port, const std::string &host, bool block) {
    return startNoWebSocket(port, host, block);
}

CPPJSLIB_MAYBE_UNUSED CPPJSLIB_EXPORT bool
WebGUI::start(int port, int websocketPort, const std::string &host, bool block)
#else

CPPJSLIB_MAYBE_UNUSED CPPJSLIB_EXPORT bool WebGUI::start(int port, const std::string &host, bool block)
#endif //CPPJSLIB_ENABLE_WEBSOCKET
{
    log("Starting servers");
    //Check if this is started or websocket-only
    if (websocket_only) {
        err("WebGUI is already started in websocket-only mode");
        return false;
    }

    if (running) {
        err("WebGUI is already running");
        return false;
    }

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
    if (port < 0) {
        return startNoWeb(websocketPort, host, block);
    }

    if (websocketPort < 0) {
        return startNoWebSocket(port, host, block);
    }
#else
    if (port < 0) {
        err("Cannot start servers with a negative port number");
        return false;
    }
#endif //CPPJSLIB_ENABLE_WEBSOCKET

    // Check if the ports are occupied, if enabled
    if (check_ports) {
        int _err = 0;
        if (port_is_in_use(host.c_str(), port, _err)) {
            err("port " + std::to_string(port) + " is already in use");
            return false;
        } else if (_err != 0) {
            err("port_is_in_use finished with code " + std::to_string(_err));
        }

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
        if (port_is_in_use(host.c_str(), websocketPort, _err)) {
            err("[CppJsLib] port " + std::to_string(websocketPort) + " is already in use");
            return false;
        } else if (_err != 0) {
            err("[CppJsLib] port_is_in_use finished with code " + std::to_string(_err));
        }
#endif //CPPJSLIB_ENABLE_WEBSOCKET
    }

    log("Starting web server");
    auto CppJsLibJsHandler = [this](const httplib::Request &req, httplib::Response &res) {
        std::ifstream inFile;
        inFile.open("CppJsLibJs/CppJsLib.js");
        if (!inFile.is_open()) {
            err("Could not open CppJsLibJs/CppJsLib.js");
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
    init_ws_json["host"] = host;
    init_ws_json["port"] = websocketPort;
#   ifdef CPPJSLIB_ENABLE_HTTPS
    if (ssl) {
        init_ws_json["tls"] = "true";
        if (fallback_plain) {
            init_ws_json["fallback_plain"] = "true";
            init_ws_json["fallback_plain_port"] = fallback_plain;
        } else {
            init_ws_json["fallback_plain"] = "false";
        }
    } else {
        init_ws_json["tls"] = "false";
    }
#   else
    init_ws_json["tls"] = "false";
#   endif //CPPJSLIB_ENABLE_HTTPS
#else
    init_ws_json["ws"] = "false";
#endif //CPPJSLIB_ENABLE_WEBSOCKET

    std::string init_ws_string = init_ws_json.dump();

    auto init_ws_handler = [init_ws_string](const httplib::Request &req, httplib::Response &res) {
        res.set_content(init_ws_string, "text/plain");
    };

#ifdef CPPJSLIB_ENABLE_HTTPS
    if (ssl) {
        std::static_pointer_cast<httplib::SSLServer>(server)->Get("/CppJsLib.js", CppJsLibJsHandler);
        std::static_pointer_cast<httplib::SSLServer>(server)->Get("/init", initHandler);
        std::static_pointer_cast<httplib::SSLServer>(server)->Get("/init_ws", init_ws_handler);
    } else {
        std::static_pointer_cast<httplib::Server>(server)->Get("/init", initHandler);
        std::static_pointer_cast<httplib::Server>(server)->Get("/CppJsLib.js", CppJsLibJsHandler);
        std::static_pointer_cast<httplib::Server>(server)->Get("/init_ws", init_ws_handler);
    }
#else
    std::static_pointer_cast<httplib::Server>(server)->Get("/init", initHandler);
    std::static_pointer_cast<httplib::Server>(server)->Get("/CppJsLib.js", CppJsLibJsHandler);
    std::static_pointer_cast<httplib::Server>(server)->Get("/init_ws", init_ws_handler);
#endif //CPPJSLIB_ENABLE_HTTPS

    // Start SSE listeners
    // Source: https://github.com/yhirose/cpp-httplib/blob/master/example/sse.cc
#ifndef CPPJSLIB_ENABLE_WEBSOCKET
    for (const std::string &s : sseVec) {
        auto *ed = new EventDispatcher();

        auto sseHandler = [&, ed](const httplib::Request &, httplib::Response &res) {
            log("Client connected to server sent event");
            res.set_header("Content-Type", "text/event-stream");
            res.set_chunked_content_provider([ed](uint64_t, httplib::DataSink &sink) {
                ed->wait_event(&sink);
                return true;
            });
        };

        sseEventMap.insert(std::pair<std::string, void *>(s, (void *) ed));

        std::string pattern = "/ev_";
        pattern.append(s);
        log("Adding SSE listen pattern: " + pattern);
#   ifdef CPPJSLIB_ENABLE_HTTPS
        if (ssl) {
            std::static_pointer_cast<httplib::SSLServer>(server)->Get(pattern.c_str(), sseHandler);
        } else {
            std::static_pointer_cast<httplib::Server>(server)->Get(pattern.c_str(), sseHandler);
        }
#   else
        std::static_pointer_cast<httplib::Server>(server)->Get(pattern.c_str(), sseHandler);
#   endif //CPPJSLIB_ENABLE_HTTPS
    }

    sseVec.clear();
#endif //CPPJSLIB_ENABLE_WEBSOCKET

    running = true;
    bool *runningPtr = &running;
    bool *stoppedPtr = &stopped;

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
    bool wsRunning;
#   ifdef CPPJSLIB_ENABLE_HTTPS
    if (ssl) {
        log("Starting tls websocket server");
        wsRunning = startNoWeb_f(std::static_pointer_cast<wspp::server_tls>(ws_server), host, websocketPort, false, "",
                                 std::map<std::string, PostHandler>(), _errorF, _loggingF, false, jsFnCallbacks);
    } else {
        log("Starting websocket server");
        wsRunning = startNoWeb_f(std::static_pointer_cast<wspp::server>(ws_server), host, websocketPort, false, "",
                                 std::map<std::string, PostHandler>(), _errorF, _loggingF, false, jsFnCallbacks);
    }

    if (fallback_plain) {
        log("Starting websocket plain fallback server");
        wsRunning = wsRunning &&
                    startNoWeb_f(std::static_pointer_cast<wspp::server>(ws_plain_server), host, websocketPort, false,
                                 "", std::map<std::string, PostHandler>(), _errorF, _loggingF, false, jsFnCallbacks);
    }
#   else
    log("Starting websocket server");
    wsRunning = startNoWeb_f(std::static_pointer_cast<wspp::server>(ws_server), host, websocketPort, false, "",
                 std::map<std::string, PostHandler>(), _errorF, _loggingF, false, jsFnCallbacks);
#   endif //CPPJSLIB_ENABLE_HTTPS
#endif //CPPJSLIB_ENABLE_WEBSOCKET

    std::function < void() > func;
#ifdef CPPJSLIB_ENABLE_HTTPS
    if (ssl) {
        log("Starting ssl web server");
        std::shared_ptr<httplib::SSLServer> svr = std::static_pointer_cast<httplib::SSLServer>(server);
        func = [svr, host, port, runningPtr, stoppedPtr, this]() {
            if (!svr->listen(host.c_str(), port)) {
                err("Could not start ssl web server");
                (*runningPtr) = false;
            }

            (*stoppedPtr) = true;
        };
    } else {
        log("Starting web server");
        std::shared_ptr<httplib::Server> svr = std::static_pointer_cast<httplib::Server>(server);
        func = [svr, host, port, runningPtr, stoppedPtr, this]() {
            if (!svr->listen(host.c_str(), port)) {
                err("Could not start web server");
                (*runningPtr) = false;
            }

            (*stoppedPtr) = true;
        };
    }
#else
    std::shared_ptr<httplib::Server> svr = std::static_pointer_cast<httplib::Server>(server);
    func = [svr, host, port, runningPtr, stoppedPtr, this]() {
        if (!svr->listen(host.c_str(), port)) {
            err("Could not start web server");
            (*runningPtr) = false;
        }

        (*stoppedPtr) = true;
    };
#endif //CPPJSLIB_ENABLE_HTTPS

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

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
    return running && wsRunning;
#else
    return running;
#endif //CPPJSLIB_ENABLE_WEBSOCKET
}

CPPJSLIB_EXPORT void WebGUI::callFromPost(const char *target, const PostHandler &handler) {
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
    websocketTargets.insert(std::make_pair(std::string(target), handler));
#endif //CPPJSLIB_ENABLE_WEBSOCKET

    auto f = [handler](const httplib::Request &req, httplib::Response &res) {
        bool hasResult;
        std::string result = handler(req.body, hasResult);
        if (hasResult) {
            res.set_content(result, "text/plain");
        }
    };

#ifdef CPPJSLIB_ENABLE_HTTPS
    if (ssl)
        std::static_pointer_cast<httplib::SSLServer>(server)->Post(target, f);
    else
        std::static_pointer_cast<httplib::Server>(server)->Post(target, f);
#else
    std::static_pointer_cast<httplib::Server>(server)->Post(target, f);
#endif //CPPJSLIB_ENABLE_HTTPS

}

CPPJSLIB_EXPORT void WebGUI::setLoggerFunc(const std::function<void(const char *)> &f) {
    _loggingF = [f](const std::string &s) {
        size_t strLen = strlen(s.c_str()) + 1;
        char *c = (char *) calloc(strLen, sizeof(char));
        memcpy(c, s.c_str(), strLen);
        f(c);
    };
}

CPPJSLIB_EXPORT void WebGUI::setErrorFunc(const std::function<void(const char *)> &f) {
    _errorF = [f](const std::string &s) {
        size_t strLen = strlen(s.c_str()) + 1;
        char *c = (char *) calloc(strLen, sizeof(char));
        memcpy(c, s.c_str(), strLen);
        f(c);
    };
}

#ifdef CPPJSLIB_ENABLE_WEBSOCKET

// Source: https://stackoverflow.com/a/440240
std::string gen_random(const int len) {
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

CPPJSLIB_EXPORT void WebGUI::setWebSocketOpenHandler(const std::function<void()> &handler) {
#   ifdef CPPJSLIB_ENABLE_HTTPS
    if (ssl) {
        std::static_pointer_cast<wspp::server_tls>(ws_server)->set_open_handler([handler](auto hdl) {
            handler();
        });
    } else {
        std::static_pointer_cast<wspp::server>(ws_server)->set_open_handler([handler](auto hdl) {
            handler();
        });
    }
#   else
    std::static_pointer_cast<wspp::server>(ws_server)->set_open_handler([handler](auto hdl) {
        handler();
    });
#   endif //CPPJSLIB_ENABLE_HTTPS

}

CPPJSLIB_EXPORT void WebGUI::setWebSocketCloseHandler(const std::function<void()> &handler) {
#   ifdef CPPJSLIB_ENABLE_HTTPS
    if (ssl) {
        std::static_pointer_cast<wspp::server_tls>(ws_server)->set_close_handler([handler](auto hdl) {
            handler();
        });
    } else {
        std::static_pointer_cast<wspp::server>(ws_server)->set_close_handler([handler](auto hdl) {
            handler();
        });
    }
#   else
    std::static_pointer_cast<wspp::server>(ws_server)->set_close_handler([handler](auto hdl) {
        handler();
    });
#   endif //CPPJSLIB_ENABLE_HTTPS

}

#endif //CPPJSLIB_ENABLE_WEBSOCKET

CPPJSLIB_EXPORT void WebGUI::call_jsFn(std::vector<std::string> *argV, const char *funcName,
                                       CPPJSLIB_MAYBE_UNUSED std::vector<std::string> *results,
                                       CPPJSLIB_MAYBE_UNUSED int wait) {
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
    if (no_websocket) {
        if (results) {
            err("Cannot call a JavaScript function with a return value because the websocket server was disabled");
            return;
        }

        nlohmann::json j;
        if (!argV->empty()) {
            for (std::string s: *argV) {
                j[funcName].push_back(s);
            }
        } else {
            j[funcName].push_back("");
        }

        std::string str = j.dump();
        log("Calling js function via server sent events: " + str);

        auto it = sseEventMap.find(std::string(funcName));
        if (it != sseEventMap.end()) {
            auto ed = (EventDispatcher *) it->second;
            ed->send_event(str);
        }
    } else {
        // Dump the list of arguments into a json string
        nlohmann::json j;
        if (!argV->empty()) {
            for (std::string s: *argV) {
                j[funcName].push_back(s);
            }
        } else {
            j[funcName].push_back("");
        }

        std::shared_ptr<wspp::con_list> list = std::static_pointer_cast<wspp::con_list>(ws_connections);

        // Set the message handlers if the function is non-void
        std::string callback = gen_random(40);
        if (results) {
            log("Waiting for results from javascript");
            while (jsFnCallbacks.count(callback) != 0) {
                callback = gen_random(40);
            }

            j["callback"] = callback;
            jsFnCallbacks.insert(std::make_pair(callback, results));
        }

        std::string str = j.dump();
        log("Calling js function via websocket: " + str);

        // Send request to all clients
        log("Sending request");
        for (const auto &it : *list) {
            try {
#   ifdef CPPJSLIB_ENABLE_HTTPS
                if (ssl) {
                    std::static_pointer_cast<wspp::server_tls>(ws_server)->send(it, str,
                                                                                websocketpp::frame::opcode::value::text);
                } else {
                    std::static_pointer_cast<wspp::server>(ws_server)->send(it, str,
                                                                            websocketpp::frame::opcode::value::text);
                }

#   else
                std::static_pointer_cast<wspp::server>(ws_server)->send(it, str, websocketpp::frame::opcode::value::text);
#   endif //CPPJSLIB_ENABLE_HTTPS
            } catch (...) {
                err("Could not send message");
            }
        }

#   ifdef CPPJSLIB_ENABLE_HTTPS
        if (fallback_plain) {
            log("Sending message to websocket plain fallback server");
            std::shared_ptr<wspp::con_list> plain_list = std::static_pointer_cast<wspp::con_list>(ws_plain_connections);
            for (const auto &it : *plain_list) {
                try {
                    std::static_pointer_cast<wspp::server>(ws_plain_server)->send(it, str,
                                                                                  websocketpp::frame::opcode::value::text);
                } catch (...) {
                    err("Could not send message");
                }
            }
        }
#   endif //CPPJSLIB_ENABLE_HTTPS

        if (results) {
            // Wait for the results to come in
            if (wait != -1) wait *= 100;
            int counter = 0;
            while (results->size() < list->size() && counter < wait) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                if (wait != -1) counter++;
            }

            // Remove the message handler
            if (jsFnCallbacks.find(callback) != jsFnCallbacks.end()) {
                jsFnCallbacks.erase(jsFnCallbacks.find(callback));
            }
        }
    }
#else
    nlohmann::json j;
    if (!argV->empty()) {
        for (std::string s: *argV) {
            j[funcName].push_back(s);
        }
    } else {
        j[funcName].push_back("");
    }

    std::string str = j.dump();
    log("Calling js function via server sent events: " + str);

    auto it = sseEventMap.find(std::string(funcName));
    if (it != sseEventMap.end()) {
        auto ed = (EventDispatcher *) it->second;
        ed->send_event(str);
    }
#endif //CPPJSLIB_ENABLE_WEBSOCKET
}

CPPJSLIB_EXPORT void WebGUI::log(const std::string &msg) {
    _loggingF(msg);
}

CPPJSLIB_EXPORT void WebGUI::err(const std::string &msg) {
    _errorF(msg);
}

CPPJSLIB_EXPORT void WebGUI::pushToVoidPtrVector(void *f) {
    voidPtrVector.push_back(f);
}

CPPJSLIB_EXPORT void WebGUI::pushToStrVecVector(std::vector<std::string> *v) {
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
        std::static_pointer_cast<httplib::Server>(server)->set_mount_point(mnt, dir);
#else
    std::static_pointer_cast<httplib::Server>(server)->set_mount_point(mnt, dir);
#endif //CPPJSLIB_ENABLE_HTTPS

}

CPPJSLIB_EXPORT void WebGUI::remove_mount_point(const char *mnt) {
#ifdef CPPJSLIB_ENABLE_HTTPS
    if (ssl)
        std::static_pointer_cast<httplib::SSLServer>(server)->remove_mount_point(mnt);
    else
        std::static_pointer_cast<httplib::Server>(server)->remove_mount_point(mnt);
#else
    std::static_pointer_cast<httplib::Server>(server)->remove_mount_point(mnt);
#endif //CPPJSLIB_ENABLE_HTTPS
}

CPPJSLIB_EXPORT bool WebGUI::isRunning() {
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
    if (websocket_only) {
#   ifdef CPPJSLIB_ENABLE_HTTPS
        if (ssl) {
            return std::static_pointer_cast<wspp::server_tls>(ws_server)->is_listening();
        } else {
            return std::static_pointer_cast<wspp::server>(ws_server)->is_listening();
        }
#   else
        return std::static_pointer_cast<wspp::server>(ws_server)->is_listening();
#   endif //CPPJSLIB_ENABLE_HTTPS
    } else {
        if (no_websocket) {
#   ifdef CPPJSLIB_ENABLE_HTTPS
            if (ssl) {
                return std::static_pointer_cast<wspp::server_tls>(ws_server)->is_listening();
            } else {
                return std::static_pointer_cast<wspp::server>(ws_server)->is_listening();
            }
#   else
            return std::static_pointer_cast<wspp::server>(ws_server)->is_listening();
#   endif //CPPJSLIB_ENABLE_HTTPS
        } else {
#   ifdef CPPJSLIB_ENABLE_HTTPS
            if (ssl) {
                return std::static_pointer_cast<httplib::SSLServer>(server)->is_running();
            } else {
                return std::static_pointer_cast<httplib::Server>(server)->is_running();
            }
#   else
            return std::static_pointer_cast<httplib::Server>(server)->is_running();
#   endif //CPPJSLIB_ENABLE_HTTPS
        }
    }
#else
#   ifdef CPPJSLIB_ENABLE_HTTPS
    if (ssl) {
        return std::static_pointer_cast<httplib::SSLServer>(server)->is_running();
    } else {
        return std::static_pointer_cast<httplib::Server>(server)->is_running();
    }
#   else
    return std::static_pointer_cast<httplib::Server>(server)->is_running();
#   endif //CPPJSLIB_ENABLE_HTTPS
#endif //CPPJSLIB_ENABLE_WEBSOCKET
}

CPPJSLIB_EXPORT void WebGUI::pushToSseVec(const std::string &s) {
    sseVec.push_back(s);
}

CPPJSLIB_EXPORT bool WebGUI::isWebsocketOnly() const {
    return websocket_only;
}

CPPJSLIB_EXPORT bool WebGUI::stop() {
    log("Stopping servers");
    return CppJsLib::util::stop(this, true, -1);
}

WebGUI::~WebGUI() {
    stop();

    for (void *p : voidPtrVector) {
        free(p);
    }

    for (std::vector<std::string> *v : strVecVector) {
        std::vector<std::string>().swap(*v);
        delete v;
    }

    for (const auto &p : sseEventMap) {
        delete ((EventDispatcher *) p.second);
    }
}
