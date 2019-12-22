//
// Created by Markus on 11/12/2019.
//

#ifndef CPPJSLIB_WEBGUI_HPP
#define CPPJSLIB_WEBGUI_HPP

#include <vector>

#include "FuncTypes.hpp"
#include "FuncImporter.hpp"
#include <httplib.h>
#include <json.hpp>

#define expose(func) _exportFunction(func, #func)
#define text "text/plain"

namespace CppJsLib {
    class WebGUI {
    public:
        explicit WebGUI(const std::string &base_dir);

        template<class R, class...Args>
        inline void _exportFunction(R(*f)(Args...), std::string name) {
            if (running) {
                std::cerr << "Cannot expose function " << name << " since the web server is already running"
                          << std::endl;
                return;
            }
            auto exposedF = _exposeFunc(f, name);
            funcVector.push_back((void *) exposedF);

            initList[name] = exposedF->toString();
            std::string r = "/callfunc_";
            r.append(name);
            server.Post(r.c_str(), [exposedF](const httplib::Request &req, httplib::Response &res) {
                Caller::call(exposedF, res, req.body);
            });
        }

        template<class...Args>
        inline JsFunction<void(Args...)> importJsFunction(std::string FunctionName) {
            return JsFunction<void(Args...)>(FunctionName, &server);
        }

        void start(int port, const std::string &host = "localhost");

        httplib::Server *getServer();

        ~WebGUI();

    private:
        httplib::Server server;
        using json = nlohmann::json;
        json initList;
        std::vector<void *> funcVector;

        struct Caller {
            template<class R, class...Args>
            static void call(ExposedFunction<R(Args...)> *eF, httplib::Response &res, const std::string &args) {
                json j = json::parse(json::parse(args)["args"].dump());
                int size = 0;
                for (auto &it : j) size++;
                auto *argArr = new std::string[size];
                int i = 0;
                for (auto &it : j) {
                    argArr[i] = it.dump();
                    i++;
                }

                auto result = eF->operator()(size, argArr);
                res.set_content(std::to_string(result), text);
            }

            template<class...Args>
            static void call(ExposedFunction<void(Args...)> *eF, httplib::Response &res, const std::string &args) {
                json j = json::parse(json::parse(args)["args"].dump());
                int size = 0;
                for (auto &it : j) size++;
                auto *argArr = new std::string[size];
                int i = 0;
                for (auto &it : j) {
                    argArr[i] = it.dump();
                    i++;
                }

                eF->operator()(size, argArr);
            }
        };

        bool running;
    };
}

#endif //CPPJSLIB_WEBGUI_HPP
