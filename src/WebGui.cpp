//
// Created by Markus on 11/12/2019.
//

#include "WebGui.hpp"

#include <json.hpp>
#include <httplib.h>
#include <sstream>

using namespace CppJsLib;

// WebGUI class -------------------------------------------------------------------------
WebGUI::WebGUI(const std::string &base_dir) {
    auto *svr = new httplib::Server();
    server = static_cast<void *>(svr);
    running = false;
    static_cast<httplib::Server *>(server)->set_base_dir(base_dir.c_str());
}

void WebGUI::start(int port, const std::string &host) {
    auto *svr = static_cast<httplib::Server *>(server);

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
    for (std::pair<std::string, std::string> p: initMap) {
        initList[p.first] = p.second;
    }
    std::map<std::string, std::string>().swap(initMap);

    std::string serialized_string = initList.dump();
    svr->Get("/init", [serialized_string](const httplib::Request &req, httplib::Response &res) {
        res.set_content(serialized_string, "text/plain");
    });

    if (svr->listen(host.c_str(), port)) {
        running = true;
    }
}

void WebGUI::callFromPost(const char *target, const PostHandler &handler) {
    auto *svr = static_cast<httplib::Server *>(server);
    svr->Post(target, [handler](const httplib::Request &req, httplib::Response &res) {
        std::string result = handler(req.body);
        if (!result.empty()) {
            res.set_content(result, "text/plain");
        }
    });
}

WebGUI::~WebGUI() {
    if (running) static_cast<httplib::Server *>(server)->stop();
    for (void *p : funcVector) {
        free(p);
    }
    //Clear the vector and release the memory. Source: https://stackoverflow.com/a/10465032
    std::vector<void *>().swap(funcVector);
}

// End of WebGUI class ------------------------------------------------------------------

std::string *CppJsLib::parseJSONInput(int *size, const std::string &args) {
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

std::string CppJsLib::stringArrayToJSON(std::vector<std::string> *v) {
    nlohmann::json json(*v);
    return json.dump();
}

std::string CppJsLib::stringToJSON(std::string s) {
    nlohmann::json json(s);
    return json.dump();
}

std::string *CppJsLib::createStringArrayFromJSON(int *size, const std::string &data) {
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

void CppJsLib::init_jsFn(const char *pattern, void *httplib_server, std::vector<void *> *responses, bool *resolved) {
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

void CppJsLib::call_jsFn(std::vector<std::string> *argV, std::vector<void *> *responses, bool *resolved) {
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
