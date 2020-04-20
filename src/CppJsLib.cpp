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
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
        if (webGui->isWebsocketOnly()) {
#   ifdef CPPJSLIB_ENABLE_HTTPS
            if (webGui->ssl) {
                webGui->getTLSWebServer()->stop_listening();
                webGui->getTLSWebServer()->stop();
            } else {
                webGui->getWebServer()->stop_listening();
                webGui->getWebServer()->stop();
            }
#   else
            webGui->getWebServer()->stop();
#   endif //CPPJSLIB_ENABLE_HTTPS
        } else {
#   ifdef CPPJSLIB_ENABLE_HTTPS
            if (webGui->ssl) {
                webGui->getHttpsServer()->stop();
            } else {
                webGui->getHttpServer()->stop();
            }
#   else
            webGui->getHttpServer()->stop();
#   endif //CPPJSLIB_ENABLE_HTTPS
        }
#else
#   ifdef CPPJSLIB_ENABLE_HTTPS
        if (ssl) {
            webGui->getHttpsServer()->stop();
        } else {
            webGui->getHttpServer()->stop();
        }
#   else
        webGui->getHttpServer()->stop();
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

CPPJSLIB_EXPORT void CppJsLib::util::callJsFunc(WebGUI *wGui, std::vector<std::string> *argV, char *funcName,
                                                std::vector<std::string> *results, int wait) {
    wGui->call_jsFn(argV, funcName, results, wait);
}

#ifndef CPPJSLIB_ENABLE_WEBSOCKET

CPPJSLIB_EXPORT void CppJsLib::util::pushToSseVector(WebGUI *webGui, const std::string &s) {
    webGui->pushToSseVec(s);
}

#endif //CPPJSLIB_ENABLE_WEBSOCKET

CPPJSLIB_EXPORT void CppJsLib::setLogger(const std::function<void(const std::string &)> &f) {
    setLoggingF(f);
}

CPPJSLIB_EXPORT void CppJsLib::setError(const std::function<void(const std::string &)> &f) {
    setErrorF(f);
}

CPPJSLIB_EXPORT void CppJsLib::util::pushToStrVecVector(WebGUI *webGui, std::vector<std::string> *v) {
    webGui->pushToStrVecVector(v);
}

CPPJSLIB_EXPORT void CppJsLib::util::pushToVoidPtrVector(WebGUI *webGui, void *ptr) {
    webGui->pushToVoidPtrVector(ptr);
}

