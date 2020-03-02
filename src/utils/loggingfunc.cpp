//
// Created by markus on 02/03/2020.
//

#include "loggingfunc.hpp"

#include <utility>

std::function<void(const std::string &)> _loggingF = nullptr;
std::function<void(const std::string &)> _errorF = nullptr;

void loggingF(const std::string &s) {
    if (_loggingF)
        _loggingF(s);
}

void errorF(const std::string &s) {
    if (_errorF)
        _errorF(s);
}

void setLoggingF(std::function<void(const std::string &)> f) {
    _loggingF = std::move(f);
}

void setErrorF(std::function<void(const std::string &)> f) {
    _errorF = std::move(f);
}
