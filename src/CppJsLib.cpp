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

#ifdef CPPJSLIB_ENABLE_HTTPS
#   define CPPJSLIB_DISABLE_SSL_MACRO ,ssl(false)
#else
#   define CPPJSLIB_DISABLE_SSL_MACRO
#endif

// WebGUI class -------------------------------------------------------------------------
CPPJSLIB_EXPORT WebGUI::WebGUI(const std::string &base_dir)
        : initMap(), funcVector(), jsFuncVector()CPPJSLIB_DISABLE_SSL_MACRO {
    auto *svr = new httplib::Server();
    server = static_cast<void *>(svr);

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

    static_cast<httplib::Server *>(server)->set_base_dir(base_dir.c_str());
}

#ifdef CPPJSLIB_ENABLE_HTTPS

CPPJSLIB_EXPORT WebGUI::WebGUI(const std::string &base_dir, bool enableSsl, const std::string &cert_path,
                               const std::string &private_key_path)
        : initMap(), funcVector(), jsFuncVector(), ssl(enableSsl) {
    if (ssl && !cert_path.empty() && !private_key_path.empty()) {
        auto *svr = new httplib::SSLServer(cert_path.c_str(), private_key_path.c_str());
        server = static_cast<void *>(svr);
    } else {
        auto *svr = new httplib::Server();
        server = static_cast<void *>(svr);
    }

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

    if (ssl)
        static_cast<httplib::SSLServer *>(server)->set_base_dir(base_dir.c_str());
    else
        static_cast<httplib::Server *>(server)->set_base_dir(base_dir.c_str());
}

#endif

CPPJSLIB_EXPORT bool WebGUI::start(int port, const std::string &host, bool block) {
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

#ifdef CPPJSLIB_ENABLE_HTTPS
    if (ssl)
        static_cast<httplib::SSLServer *>(server)->Get("/CppJsLib.js", CppJsLibJsHandler);
    else
#endif
    static_cast<httplib::Server *>(server)->Get("/CppJsLib.js", CppJsLibJsHandler);

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

#ifdef CPPJSLIB_ENABLE_HTTPS
    if (ssl)
        static_cast<httplib::SSLServer *>(server)->Get("/init", initHandler);
    else
#endif
    static_cast<httplib::Server *>(server)->Get("/init", initHandler);

    running = true;
    bool *runningPtr = &running;
    bool *stoppedPtr = &stopped;

    std::function < void() > func;
#ifdef CPPJSLIB_ENABLE_HTTPS
    if (ssl) {
        auto *svr = static_cast<httplib::SSLServer *>(server);
        func = [svr, host, port, runningPtr, stoppedPtr]() {
            if (!svr->listen(host.c_str(), port)) {
                (*runningPtr) = false;
            }

            (*stoppedPtr) = true;
        };
    } else {
#endif
    auto *svr = static_cast<httplib::Server *>(server);
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
        static_cast<httplib::SSLServer *>(server)->Get(target, f);
    else
#endif
    static_cast<httplib::Server *>(server)->Get(target, f);
}

CPPJSLIB_EXPORT void WebGUI::setLogger(std::function<void(const std::string &)> loggingFunction) {
    _loggingF = std::move(loggingFunction);
}

CPPJSLIB_EXPORT void WebGUI::setError(std::function<void(const std::string &)> errorFunction) {
    _errorF = std::move(errorFunction);
}

CPPJSLIB_EXPORT WebGUI::~WebGUI() {
    stop(this);
#ifdef CPPJSLIB_ENABLE_HTTPS
    if (ssl)
        delete static_cast<httplib::SSLServer *>(server);
    else
#endif
    delete static_cast<httplib::Server *>(server);

    for (void *p : funcVector) {
        delete static_cast<ExposedFunction<void()> *>(p);
    }

    for (void *p : jsFuncVector) {
        free(p);
    }
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

CPPJSLIB_EXPORT void
CppJsLib::init_jsFn(const char *pattern, void *httplib_server, bool ssl, std::vector<void *> *responses,
                    bool *resolved) {
    auto f = [responses, resolved](const httplib::Request &req, httplib::Response &res) {
        responses->push_back(static_cast<void *>(&res));
        do {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        } while (!(*resolved));
        std::vector<void *>().swap(*responses);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));

        *resolved = false;
    };

#ifdef CPPJSLIB_ENABLE_HTTPS
    if (ssl)
        static_cast<httplib::SSLServer *>(httplib_server)->Get(pattern, f);
    else
#endif
    static_cast<httplib::Server *>(httplib_server)->Get(pattern, f);
}

CPPJSLIB_EXPORT void
CppJsLib::init_jsFn(const char *pattern, void *httplib_server, bool ssl, std::vector<void *> *responses,
                    bool *resolved, std::vector<char*> *results, int wait) {
    auto f = [responses, resolved, results, wait](const httplib::Request &req, httplib::Response &res) {
        responses->push_back(static_cast<void *>(&res));
        if(!req.body.empty()) {
            results->push_back(strdup(req.body.c_str()));
        }

        do {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        } while (!(*resolved));
        std::this_thread::sleep_for(std::chrono::milliseconds(wait + 40));
        std::vector<void *>().swap(*responses);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));

        *resolved = false;
    };

#ifdef CPPJSLIB_ENABLE_HTTPS
    if (ssl)
        static_cast<httplib::SSLServer *>(httplib_server)->Get(pattern, f);
    else
#endif
    static_cast<httplib::Server *>(httplib_server)->Get(pattern, f);
}

CPPJSLIB_EXPORT void
CppJsLib::call_jsFn(std::vector<std::string> *argV, std::vector<void *> *responses, bool *resolved) {
    nlohmann::json j;
    for (std::string s: *argV) {
        j.push_back(s);
    }
    std::string str = j.dump();

    for (void *r:*responses) {
        auto *res = static_cast<httplib::Response *>(r);
        res->set_content(str, "text/plain");
        res->content_length = str.size();
    }

    *resolved = true;
}

CPPJSLIB_EXPORT void CppJsLib::setLogger(std::function<void(const std::string &)> f) {
    loggingF = std::move(f);
}

CPPJSLIB_EXPORT void CppJsLib::setError(std::function<void(const std::string &)> f) {
    errorF = std::move(f);
}

