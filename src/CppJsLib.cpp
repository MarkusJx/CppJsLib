//
// Created by Markus on 11/12/2019.
//

#include "CppJsLib.hpp"

#include <json.hpp>
#include <httplib.h>
#include <thread>

#include "utils/websocket.hpp"
#include "utils/loggingfunc.hpp"

using namespace CppJsLib;

CPPJSLIB_EXPORT bool CppJsLib::stop(WebGUI *webGui, bool block, int waitMaxSeconds) {
    if (webGui->running) {
#ifdef CPPJSLIB_ENABLE_HTTPS
        if (webGui->ssl)
            webGui->getHttpsServer()->stop();
        else
#endif //CPPJSLIB_ENABLE_HTTPS
            webGui->getHttpServer()->stop();
        if (waitMaxSeconds != CPPJSLIB_DURATION_INFINITE && block) {
            waitMaxSeconds = waitMaxSeconds * 100;
            int waited = 0;
            while (!webGui->stopped && waited < waitMaxSeconds) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                waited++;
            }

            if (!webGui->stopped) {
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
#   ifdef CPPJSLIB_ENABLE_HTTPS
    if (webGui->ssl) {
        webGui->getTLSWebServer()->stop();
        if (webGui->fallback_plain)
            webGui->getWebServer()->stop();
    } else
#   endif //CPPJSLIB_ENABLE_HTTPS
        webGui->getWebServer()->stop();
#endif //CPPJSLIB_ENABLE_WEBSOCKET

    return webGui->stopped;
}

CPPJSLIB_EXPORT std::string *CppJsLib::util::parseJSONInput(int *size, const std::string &args) {
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

CPPJSLIB_EXPORT std::string CppJsLib::util::stringArrayToJSON(std::vector<std::string> *v) {
    nlohmann::json json(*v);
    return json.dump();
}

CPPJSLIB_EXPORT std::string CppJsLib::util::stringToJSON(std::string s) {
    nlohmann::json json(s);
    return json.dump();
}

CPPJSLIB_EXPORT std::string *CppJsLib::util::createStringArrayFromJSON(int *size, const std::string &data) {
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

CPPJSLIB_EXPORT void CppJsLib::util::callJsFunc(WebGUI *wGui, std::vector<std::string> *argV, char *funcName,
                                                std::vector<char *> *results, int wait) {
    wGui->call_jsFn(argV, funcName, results, wait);
}

template<typename EndpointType>
void empty_on_message(EndpointType *, const websocketpp::connection_hdl &, typename EndpointType::message_ptr) {}

CPPJSLIB_EXPORT void WebGUI::call_jsFn(std::vector<std::string> *argV, const char *funcName,
                                       std::vector<char *> *results, int wait) {
    // Dump the list of arguments into a json string
    nlohmann::json j;
    if (!argV->empty()) {
        for (std::string s: *argV) {
            j[funcName].push_back(s);
        }
    } else {
        j[funcName].push_back("");
    }

    std::string str = j.dump();

    std::shared_ptr<wspp::con_list> list = std::static_pointer_cast<wspp::con_list>(ws_connections);

    // Set the message handlers if the function is non-void
    if (results) {
#   ifdef CPPJSLIB_ENABLE_HTTPS
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
#   endif //CPPJSLIB_ENABLE_HTTPS
            std::shared_ptr<wspp::server> ws_svr = std::static_pointer_cast<wspp::server>(ws_server);
            ws_svr->set_message_handler(bind([results](wspp::server *s, const websocketpp::connection_hdl &hdl,
                                                       const wspp::server::message_ptr &msg) {
                results->push_back(strdup(msg->get_payload().c_str()));
            }, ws_svr.get(), ::_1, ::_2));
#   ifdef CPPJSLIB_ENABLE_HTTPS
        }
#   endif //CPPJSLIB_ENABLE_HTTPS
    }

    // Send request to all clients
    for (const auto &it : *list) {
#   ifdef CPPJSLIB_ENABLE_HTTPS
        if (ssl) {
            std::static_pointer_cast<wspp::server_tls>(ws_server)->send(it, str,
                                                                        websocketpp::frame::opcode::value::text);
        } else
#   endif //CPPJSLIB_ENABLE_HTTPS
            std::static_pointer_cast<wspp::server>(ws_server)->send(it, str, websocketpp::frame::opcode::value::text);
    }

#   ifdef CPPJSLIB_ENABLE_HTTPS
    if (fallback_plain) {
        std::shared_ptr<wspp::con_list> plain_list = std::static_pointer_cast<wspp::con_list>(ws_plain_connections);
        for (const auto &it : *plain_list) {
            std::static_pointer_cast<wspp::server>(ws_plain_server)->send(it, str,
                                                                          websocketpp::frame::opcode::value::text);
        }
    }
#   endif //CPPJSLIB_ENABLE_HTTPS

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
#   ifdef CPPJSLIB_ENABLE_HTTPS
    if (ssl) {
        std::shared_ptr<wspp::server_tls> ws_svr = std::static_pointer_cast<wspp::server_tls>(ws_server);
        ws_svr->set_message_handler(bind(&empty_on_message<wspp::server_tls>, ws_svr.get(), ::_1, ::_2));
        if (fallback_plain) {
            std::shared_ptr<wspp::server> ws_plain_svr = std::static_pointer_cast<wspp::server>(ws_plain_server);
            ws_plain_svr->set_message_handler(bind(&empty_on_message<wspp::server>, ws_plain_svr.get(), ::_1, ::_2));
        }
    } else {
#   endif //CPPJSLIB_ENABLE_HTTPS
        std::shared_ptr<wspp::server> ws_svr = std::static_pointer_cast<wspp::server>(ws_server);
        ws_svr->set_message_handler(bind(&empty_on_message<wspp::server>, ws_svr.get(), ::_1, ::_2));
#   ifdef CPPJSLIB_ENABLE_HTTPS
    }
#   endif //CPPJSLIB_ENABLE_HTTPS
}

#endif //CPPJSLIB_ENABLE_WEBSOCKET

CPPJSLIB_EXPORT void CppJsLib::setLogger(const std::function<void(const std::string &)> &f) {
    setLoggingF(f);
}

CPPJSLIB_EXPORT void CppJsLib::setError(const std::function<void(const std::string &)> &f) {
    setErrorF(f);
}

#if defined(CPPJSLIB_BUILD_LIB) || !defined (CPPJSLIB_STATIC_DEFINE)

#ifdef CPPJSLIB_ENABLE_HTTPS

CPPJSLIB_EXPORT void CppJsLib::createWebGUI(WebGUI *&webGui, const std::string &base_dir, const std::string &cert_path,
                                            const std::string &private_key_path,
                                            unsigned short websocket_plain_fallback_port) {
        webGui = new WebGUI(base_dir, cert_path, private_key_path, websocket_plain_fallback_port);
}

#endif

CPPJSLIB_EXPORT void CppJsLib::createWebGUI(WebGUI *&webGui, const std::string &base_dir) {
    webGui = new CppJsLib::WebGUI(base_dir);
}

CPPJSLIB_EXPORT void CppJsLib::deleteWebGUI(WebGUI *&webGui) {
    delete webGui;
}

#endif //CPPJSLIB_BUILD_LIB

