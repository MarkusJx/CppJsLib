//
// Created by markus on 02/03/2020.
//

#include "loggingfunc.hpp"
#include "../CppJsLib.hpp"

#include <utility>

std::function<void(const std::string &)> _loggingF = nullptr;
std::function<void(const std::string &)> _errorF = nullptr;

bool _ok = true;
std::string lastError;

CPPJSLIB_EXPORT bool CppJsLib::ok() {
    return _ok;
}

CPPJSLIB_EXPORT std::string CppJsLib::getLastError() {
    return lastError;
}

CPPJSLIB_EXPORT void CppJsLib::resetLastError() {
    _ok = true;
    lastError = "";
}

void loggingF(const std::string &s) {
    if (_loggingF)
        _loggingF(s);
}

void errorF(const std::string &s) {
    if (_errorF)
        _errorF(s);
    _ok = false;
    lastError = s;
}

void setLoggingF(std::function<void(const std::string &)> f) {
    _loggingF = std::move(f);
}

void setErrorF(std::function<void(const std::string &)> f) {
    _errorF = std::move(f);
}
