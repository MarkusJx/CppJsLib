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

CPPJSLIB_EXPORT bool CppJsLib::util::stop(WebGUI *webGui, bool block, int waitMaxSeconds) {
    if (webGui->isRunning()) {
#ifdef CPPJSLIB_ENABLE_HTTPS
        if (webGui->ssl)
            webGui->getHttpsServer()->stop();
        else
            webGui->getHttpServer()->stop();
#else
        webGui->getHttpServer()->stop();
#endif //CPPJSLIB_ENABLE_HTTPS

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
#   ifdef CPPJSLIB_ENABLE_HTTPS
        if (webGui->ssl) {
            webGui->getTLSWebServer()->stop();
            if (webGui->fallback_plain)
                webGui->getWebServer()->stop();
        } else {
            webGui->getWebServer()->stop();
        }
#   else
        webGui->getWebServer()->stop();
#   endif //CPPJSLIB_ENABLE_HTTPS
#endif //CPPJSLIB_ENABLE_WEBSOCKET

        if (waitMaxSeconds != CPPJSLIB_DURATION_INFINITE && block) {
            waitMaxSeconds = waitMaxSeconds * 100;
            int waited = 0;
            while (webGui->isRunning() && waited < waitMaxSeconds) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                waited++;
            }

            if (webGui->isRunning()) {
                errorF("Timed out during socket close");
            }
        } else if (block) {
            while (webGui->isRunning()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }
    }
    webGui->running = webGui->isRunning();

    return !webGui->isRunning();
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
                                                std::vector<std::string> *results, int wait) {
    wGui->call_jsFn(argV, funcName, results, wait);
}

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

CPPJSLIB_EXPORT void WebGUI::call_jsFn(std::vector<std::string> *argV, const char *funcName,
                                       std::vector<std::string> *results, int wait) {
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
        while (jsFnCallbacks.count(callback) != 0) {
            callback = gen_random(40);
        }

        j["callback"] = callback;
        jsFnCallbacks.insert(std::make_pair(callback, results));
    }

    std::string str = j.dump();

    // Send request to all clients
    for (const auto &it : *list) {
#   ifdef CPPJSLIB_ENABLE_HTTPS
        if (ssl) {
            std::static_pointer_cast<wspp::server_tls>(ws_server)->send(it, str,
                                                                        websocketpp::frame::opcode::value::text);
        } else {
            std::static_pointer_cast<wspp::server>(ws_server)->send(it, str, websocketpp::frame::opcode::value::text);
        }
#   else
        std::static_pointer_cast<wspp::server>(ws_server)->send(it, str, websocketpp::frame::opcode::value::text);
#   endif //CPPJSLIB_ENABLE_HTTPS
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

#endif //CPPJSLIB_ENABLE_WEBSOCKET

CPPJSLIB_EXPORT void CppJsLib::setLogger(const std::function<void(const std::string &)> &f) {
    setLoggingF(f);
}

CPPJSLIB_EXPORT void CppJsLib::setError(const std::function<void(const std::string &)> &f) {
    setErrorF(f);
}

#if defined(CPPJSLIB_BUILD_LIB) || !defined (CPPJSLIB_STATIC_DEFINE)

#ifdef CPPJSLIB_ENABLE_HTTPS

CPPJSLIB_EXPORT WebGUI* CppJsLib::createWebGUI(const std::string &base_dir, const std::string &cert_path,
                                            const std::string &private_key_path,
                                            unsigned short websocket_plain_fallback_port) {
    return new WebGUI(base_dir, cert_path, private_key_path, websocket_plain_fallback_port);
}

#endif

CPPJSLIB_EXPORT WebGUI* CppJsLib::createWebGUI(const std::string &base_dir) {
    return new CppJsLib::WebGUI(base_dir);
}

CPPJSLIB_EXPORT void CppJsLib::deleteWebGUI(WebGUI *webGui) {
    delete webGui;
}

#endif //CPPJSLIB_BUILD_LIB

CPPJSLIB_EXPORT void CppJsLib::util::pushToStrVecVector(WebGUI *webGui, std::vector<std::string> *v) {
    webGui->pushToStrVecVector(v);
}

CPPJSLIB_EXPORT void CppJsLib::util::pushToVoidPtrVector(WebGUI *webGui, void *ptr) {
    webGui->pushToVoidPtrVector(ptr);
}

