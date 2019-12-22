//
// Created by markus on 22/12/2019.
//

#ifndef CPPJSLIB_FUNCIMPORTER_HPP
#define CPPJSLIB_FUNCIMPORTER_HPP

#include <cstdarg>
#include <string>
#include <json.hpp>
#include <httplib.h>

namespace CppJsLib {
    template<class T>
    std::string getEl(T dt) {
        return std::to_string(dt);
    }

    template<class ...Args>
    void ConvertToString(nlohmann::json *json, Args...args) {
        auto x = {(json->push_back(args), 0)...};
    }

    template<class>
    struct JsFunction;

    template<class... Args>
    struct JsFunction<void(Args ...)> {
    public:
        explicit JsFunction(const std::string &name, httplib::Server *server) {
            std::string r = "/listenfunc_";
            r.append(name);
            server->Get(r.c_str(), [this](const httplib::Request &req, httplib::Response &res) {
                responses.push_back(&res);
                do {
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                } while (!resolved);
                std::vector<httplib::Response *>().swap(responses);
                std::this_thread::sleep_for(std::chrono::milliseconds(10));

                resolved = false;
            });
        }

        void operator()(Args ... args) {
            nlohmann::json j;
            auto x = {(ConvertToString(&j, getEl(args)), 0)...};
            std::string str = j.dump();

            for (httplib::Response *r:responses) {
                r->set_content(str, "text/plain");
            }
            resolved = true;
        }

    private:
        bool resolved = false;
        std::vector<httplib::Response *> responses;
    };
}

#endif //CPPJSLIBALL_FUNCIMPORTER_HPP
