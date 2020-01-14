//
// Created by Markus on 11/12/2019.
//

#include "CppJsLib.hpp"

#include <json.hpp>
#include <httplib.h>
#include <thread>
#include <iostream>
#include <utility>

using namespace CppJsLib;

// WebGUI class -------------------------------------------------------------------------
CPPJSLIB_EXPORT WebGUI::WebGUI(const std::string &base_dir) : initMap(), funcVector(), jsFuncVector() {
    auto *svr = new httplib::Server();
    server = static_cast<void *>(svr);
    running = false;
    stopped = false;
    loggingF = [](const std::string &) {};

    static_cast<httplib::Server *>(server)->set_base_dir(base_dir.c_str());
}

CPPJSLIB_EXPORT bool WebGUI::start(int port, const std::string &host, bool block) {
    auto *svr = static_cast<httplib::Server *>(server);

    loggingF("[CppJsLib] Starting web server");
    svr->Get("/CppJsLib.js", [](const httplib::Request &req, httplib::Response &res) {
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
    });

    nlohmann::json initList;
    for (std::pair<char *, char *> p: initMap) {
        initList[p.first] = p.second;
        free(p.first);
        free(p.second);
    }
    std::map<char *, char *>().swap(initMap);

    std::string serialized_string = initList.dump();
    svr->Get("/init", [serialized_string](const httplib::Request &req, httplib::Response &res) {
        res.set_content(serialized_string, "text/plain");
    });

    running = true;
    bool *runningPtr = &running;
    bool *stoppedPtr = &stopped;

    std::function < void() > func = [svr, host, port, runningPtr, stoppedPtr]() {
        if (!svr->listen(host.c_str(), port)) {
            (*runningPtr) = false;
        }

        (*stoppedPtr) = true;
    };

    if (!block) {
        loggingF("[CppJsLib] Starting web server in non-blocking mode");
        std::thread t(func);
        t.detach();
    } else {
        loggingF("[CppJsLib] Starting web server in blocking mode");
        func();
    }

    return running;
}

CPPJSLIB_EXPORT void WebGUI::callFromPost(const char *target, const PostHandler &handler) {
    auto *svr = static_cast<httplib::Server *>(server);
    svr->Post(target, [handler](const httplib::Request &req, httplib::Response &res) {
        std::string result = handler(req.body);
        if (!result.empty()) {
            res.set_content(result, "text/plain");
        }
    });
}

CPPJSLIB_EXPORT void WebGUI::setLogger(std::function<void(const std::string &)> f) {
    loggingF = std::move(f);
}

CPPJSLIB_EXPORT void WebGUI::setError(std::function<void(const std::string &)> f) {
    errorF = std::move(f);
}

CPPJSLIB_EXPORT WebGUI::~WebGUI() {
    stop(this);
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
        webGui->getHttpServer()->stop();
        if (waitMaxSeconds != CPPJSLIB_DURATION_INFINITE && block) {
            waitMaxSeconds = waitMaxSeconds * 100;
            int waited = 0;
            while (!webGui->stopped && waited < waitMaxSeconds) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                waited++;
            }

            if (!webGui->stopped) {
                std::cerr << "Timed out during socket close" << std::endl;
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
CppJsLib::init_jsFn(const char *pattern, void *httplib_server, std::vector<void *> *responses, bool *resolved) {
    auto *server = static_cast<httplib::Server *>(httplib_server);
    server->Get(pattern, [responses, resolved](const httplib::Request &req, httplib::Response &res) {
        responses->push_back(static_cast<void *>(&res));
        do {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        } while (!(*resolved));
        std::vector<void *>().swap(*responses);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));

        *resolved = false;
    });
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
