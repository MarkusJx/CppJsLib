//
// Created by markus on 22/12/2019.
//

#ifndef CPPJSLIB_FUNCIMPORTER_HPP
#define CPPJSLIB_FUNCIMPORTER_HPP

#include <string>
#include <vector>

namespace CppJsLib {
    template<class T>
    inline std::string getEl(T dt) {
        return std::to_string(dt);
    }

    template<class ...Args>
    inline void ConvertToString(std::vector<std::string> *argV, Args...args) {
        auto x = {(argV->push_back(args), 0)...};
    }

    void init_jsFn(const char *pattern, void *httplib_server, std::vector<void *> *responses, bool *resolved);

    void call_jsFn(std::vector<std::string> *argV, std::vector<void *> *responses, bool *resolved);

    template<class>
    struct JsFunction;

    template<class... Args>
    struct JsFunction<void(Args ...)> {
    public:
        explicit JsFunction(const std::string &name, void *httplib_server) {
            std::string r = "/listenfunc_";
            r.append(name);
            init_jsFn(r.c_str(), httplib_server, &responses, &resolved);
        }

        void operator()(Args ... args) {
            std::vector<std::string> argV;
            auto x = {(ConvertToString(&argV, getEl(args)), 0)...};
            call_jsFn(&argV, &responses, &resolved);
        }

    private:
        bool resolved = false;
        std::vector<void *> responses;
    };
}

#endif //CPPJSLIBALL_FUNCIMPORTER_HPP
