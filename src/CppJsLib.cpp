//
// Created by Markus on 11/12/2019.
//

#include "CppJsLib.hpp"

#include <json.hpp>
#include <httplib.h>
#include <thread>

#include "utils/websocket.hpp"

using namespace CppJsLib;

CPPJSLIB_EXPORT bool CppJsLib::util::stop(WebGUI *webGui, bool block, int waitMaxSeconds) {
    if (webGui->isRunning()) {
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
        if (!webGui->isWebsocketOnly()) {
            loggingF("Stopping web server");
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

        loggingF("Stopping websocket server");
        try {
#   ifdef CPPJSLIB_ENABLE_HTTPS
            if (webGui->ssl) {
                webGui->getTLSWebServer()->stop_listening();
                webGui->getTLSWebServer()->stop();
            } else {
                webGui->getWebServer()->stop_listening();
                webGui->getWebServer()->stop();
            }

            if (webGui->fallback_plain) {
                loggingF("Stopping websocket plain fallback server");
                webGui->getWebServer()->stop_listening();
                webGui->getWebServer()->stop();
            }
#   else
            webGui->getWebServer()->stop_listening();
            webGui->getWebServer()->stop();
#   endif //CPPJSLIB_ENABLE_HTTPS
        } catch (...) {
            errorF("Could not close websocket server(s)");
        }
#else
#   ifdef CPPJSLIB_ENABLE_HTTPS
        if (webGui->ssl) {
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
    } else {
        loggingF("Servers are already stopped");
    }

    webGui->running = webGui->isRunning();
    if (webGui->running) {
        errorF("Could not close all sockets");
    } else {
        loggingF("Successfully closed all sockets");
    }

    return !webGui->isRunning();
}

CPPJSLIB_EXPORT std::vector<std::string> CppJsLib::util::parseJSONInput(const std::string &args) {
    loggingF("Parsing JSON: " + args);
    try {
        using json = nlohmann::json;
        json j = json::parse(json::parse(args)["args"].dump());

        std::vector<std::string> argArr;
        for (auto &it : j) {
            argArr.push_back(it.dump());
        }

        return argArr;
    } catch (...) {
        errorF("Could not parse JSON");
    }
    return std::vector<std::string>();
}

CPPJSLIB_EXPORT std::string CppJsLib::util::stringArrayToJSON(const std::vector<std::string> &v) {
    loggingF("Converting vector to JSON string");
    try {
        nlohmann::json json(v);
        return json.dump();
    } catch (...) {
        errorF("Could not parse JSON");
    }
    return "";
}

CPPJSLIB_EXPORT std::string CppJsLib::util::stringMapToJSON(const std::map<std::string, std::string> &m) {
    loggingF("Converting map to JSON string");
    try {
        nlohmann::json json(m);
        return json.dump();
    } catch (...) {
        errorF("Could not convert map");
    }
    return "";
}

CPPJSLIB_EXPORT std::string CppJsLib::util::stringToJSON(const std::string &s) {
    loggingF("Converting string to JSON: " + s);
    try {
        nlohmann::json json(s);
        return json.dump();
    } catch (...) {
        errorF("Could not convert string");
    }
    return "";
}

CPPJSLIB_EXPORT std::vector<std::string> CppJsLib::util::createStringArrayFromJSON(const std::string &data) {
    std::vector<std::string> tmp;
    loggingF("Creating string array from JSON");

    try {
        nlohmann::json j = nlohmann::json::parse(data);
        for (auto &it : j) {
            tmp.push_back(it.dump());
        }
    } catch (...) {
        errorF("Could not parse JSON");
    }

    return tmp;
}

CPPJSLIB_EXPORT std::map<std::string, std::string> CppJsLib::util::createStringMapFromJSON(const std::string &data) {
    loggingF("Creating string map from JSON object");
    try {
        nlohmann::json j = nlohmann::json::parse(data);
        return j.get<std::map<std::string, std::string>>();
    } catch (...) {
        errorF("Could not parse JSON");
    }
    return std::map<std::string, std::string>();
}

CPPJSLIB_EXPORT void CppJsLib::util::callJsFunc(WebGUI *wGui, std::vector<std::string> *argV, char *funcName,
                                                std::vector<std::string> *results, int wait) {
    wGui->call_jsFn(argV, funcName, results, wait);
}

CPPJSLIB_EXPORT void CppJsLib::util::pushToSseVector(WebGUI *webGui, const std::string &s) {
    webGui->pushToSseVec(s);
}

CPPJSLIB_EXPORT void CppJsLib::util::setLogger(const std::function<void(const char *)> &f) {
    setLoggingF([f](const std::string &msg) {
        size_t strLen = strlen(msg.c_str()) + 1;
        char *c = (char *) calloc(strLen, sizeof(char));
        memcpy(c, msg.c_str(), strLen);
        f(c);
    });
}

CPPJSLIB_EXPORT void CppJsLib::util::setError(const std::function<void(const char *)> &f) {
    setErrorF([f](const std::string &msg) {
        size_t strLen = strlen(msg.c_str()) + 1;
        char *c = (char *) calloc(strLen, sizeof(char));
        memcpy(c, msg.c_str(), strLen);
        f(c);
    });
}

CPPJSLIB_EXPORT void CppJsLib::util::deallocateMessage(const char *data) {
    free((char *) data);
}

CPPJSLIB_EXPORT void CppJsLib::util::pushToStrVecVector(WebGUI *webGui, std::vector<std::string> *v) {
    webGui->pushToStrVecVector(v);
}

CPPJSLIB_EXPORT void CppJsLib::util::pushToVoidPtrVector(WebGUI *webGui, void *ptr) {
    webGui->pushToVoidPtrVector(ptr);
}

