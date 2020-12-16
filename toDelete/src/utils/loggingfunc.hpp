/*
 * loggingfunc.hpp
 * Declares functions for logging
 *
 * Licensed under the MIT License
 *
 * Copyright (c) 2020 MarkusJx
 *
 * The full license including third-party licenses is available at https://github.com/MarkusJx/CppJsLib/blob/master/LICENSE
 */
#ifndef CPPJSLIBALL_LOGGINGFUNC_HPP
#define CPPJSLIBALL_LOGGINGFUNC_HPP

#include <string>
#include <functional>

void loggingF(const std::string &);
void errorF(const std::string &);

void setLoggingF(std::function<void(const std::string &)>);
void setErrorF(std::function<void(const std::string &)>);

#endif //CPPJSLIBALL_LOGGINGFUNC_HPP
