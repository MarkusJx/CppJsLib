//
// Created by markus on 02/03/2020.
//

#include "loggingfunc.hpp"
#include "../CppJsLib.hpp"

#include <utility>

std::function<void(const std::string &)> logging_f = nullptr;
std::function<void(const std::string &)> error_f = nullptr;

bool ok_t = true;
std::string lastError;

CPPJSLIB_EXPORT bool CppJsLib::ok() {
    return ok_t;
}

CPPJSLIB_EXPORT std::string CppJsLib::getLastError() {
    return lastError;
}

CPPJSLIB_EXPORT void CppJsLib::resetLastError() {
    ok_t = true;
    lastError = "";
}

void loggingF(const std::string &s) {
    if (logging_f)
        logging_f(s);
}

void errorF(const std::string &s) {
    if (error_f)
        error_f(s);
    ok_t = false;
    lastError = s;
}

void setLoggingF(std::function<void(const std::string &)> f) {
    logging_f = std::move(f);
}

void setErrorF(std::function<void(const std::string &)> f) {
    error_f = std::move(f);
}


CPPJSLIB_EXPORT void CppJsLib::util::logging::log(const std::string &message) {
    loggingF(message);
}

CPPJSLIB_EXPORT void CppJsLib::util::logging::err(const std::string &message) {
    errorF(message);
}