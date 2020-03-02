//
// Created by markus on 02/03/2020.
//

#ifndef CPPJSLIBALL_LOGGINGFUNC_HPP
#define CPPJSLIBALL_LOGGINGFUNC_HPP

#include <string>
#include <functional>

void loggingF(const std::string &);
void errorF(const std::string &);

void setLoggingF(std::function<void(const std::string &)>);
void setErrorF(std::function<void(const std::string &)>);

#endif //CPPJSLIBALL_LOGGINGFUNC_HPP
