//
// Created by Markus on 11/12/2019.
//

#ifndef CPPJSLIB_WEBGUI_HPP
#define CPPJSLIB_WEBGUI_HPP

#include <map>

#include "FuncTypes.hpp"
#include "FuncImporter.hpp"

#define expose(func) _exportFunction(func, #func)
#define getHttpServer() _getHttpServer<httplib::Server*>()

namespace CppJsLib {
    std::string *parseJSONInput(int *size, const std::string &args);

    std::string stringArrayToJSON(std::vector<std::string> *v);

    std::string stringToJSON(std::string s);

    template<size_t SIZE, class T>
    inline size_t array_size(T (&arr)[SIZE]) {
        return SIZE;
    }

    template<class>
    struct TypeConverter;

    template<class R>
    struct TypeConverter<R *> {
        static std::string toString(R toConvert) {
            size_t size = array_size(toConvert);
            std::vector<std::string> stringVector;
            for (int i = 0; i < size; i++) {
                stringVector.push_back(std::to_string(toConvert[i]));
            }

            std::string res = stringArrayToJSON(&stringVector);
            std::vector<std::string>().swap(stringVector);
            return res;
        }
    };

    template<class R>
    struct TypeConverter {
        static std::string toString(R toConvert) {
            return stringToJSON(std::to_string(toConvert));
        }
    };

    struct Caller {
        template<class R, class...Args>
        static std::string call(ExposedFunction<R(Args...)> *eF, const std::string &args) {
            int size = 0;
            auto *argArr = parseJSONInput(&size, args);

            R result = eF->operator()(size, argArr);

            return TypeConverter<R>::toString(result);
        }

        template<class...Args>
        static std::string call(ExposedFunction<void(Args...)> *eF, const std::string &args) {
            int size = 0;
            auto *argArr = parseJSONInput(&size, args);

            eF->operator()(size, argArr);
            return "";
        }
    };

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
            funcVector.push_back(static_cast<void *>(exposedF));

            initMap.insert(std::pair<std::string, std::string>(name, exposedF->toString()));
            std::string r = "/callfunc_";
            r.append(name);
            callFromPost(r.c_str(), [exposedF](std::string req_body) {
                return Caller::call(exposedF, req_body);
            });
        }

        template<class...Args>
        inline JsFunction<void(Args...)> importJsFunction(std::string FunctionName) {
            return JsFunction<void(Args...)>(FunctionName, server);
        }

        void start(int port, const std::string &host = "localhost");

        /**
         * A function used by the getHttpServer macro
         *
         * @warning Please DO NOT USE this function
         * @tparam T the param to convert the server pointer to, MUST be httplib::Server*
         * @return a pointer to the http Server of this instance
         */
        template<class T>
        inline T _getHttpServer() {
            return static_cast<T>(server);
        }

        ~WebGUI();

    private:
        void *server;
        std::map<std::string, std::string> initMap;
        std::vector<void *> funcVector;
        bool running;
        using PostHandler = std::function<std::string(std::string req_body)>;

        void callFromPost(const char *target, const PostHandler &handler);
    };
}

#endif //CPPJSLIB_WEBGUI_HPP
