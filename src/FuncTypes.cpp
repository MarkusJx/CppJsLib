//
// Created by markus on 22/12/2019.
//
#include "FuncTypes.hpp"

#include <json.hpp>

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
