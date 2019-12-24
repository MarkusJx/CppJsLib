//
// Created by markus on 22/12/2019.
//
#include "FuncImporter.hpp"

#include <httplib.h>
#include <json.hpp>

void CppJsLib::init_jsFn(const char *pattern, void *httplib_server, std::vector<void *> *responses, bool *resolved) {
    auto *server = static_cast<httplib::Server *>(httplib_server);
    printf("Pattern: %s", pattern);
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