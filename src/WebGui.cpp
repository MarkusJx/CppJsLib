//
// Created by Markus on 11/12/2019.
//

#include "WebGui.hpp"

#include <json.hpp>
#include <httplib.h>
#include <sstream>

using namespace CppJsLib;

WebGUI::WebGUI(const std::string &base_dir) {
    auto *svr = new httplib::Server();
    server = static_cast<void *>(svr);
    running = false;
    static_cast<httplib::Server *>(server)->set_base_dir(base_dir.c_str());
}

void WebGUI::start(int port, const std::string &host) {
    auto *svr = static_cast<httplib::Server *>(server);

    svr->Get("/httpServer.js", [](const httplib::Request &req, httplib::Response &res) {
        std::ifstream inFile;
        inFile.open("httpServerJs/httpServer.js");

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
    static_cast<httplib::Server *>(server)->Post(target,
                                                 [handler](const httplib::Request &req, httplib::Response &res) {
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
