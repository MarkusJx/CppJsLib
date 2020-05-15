/**
 * Include this file if you are using CppJsLib with https and websocket support enabled.
 * It will automatically include CppJsLib.hpp, define the required macros and undefine
 * the macros that should not be used anywhere else or may cause problems
 */
#ifndef CPPJSLIBALL_CPPJSLIBALL_HPP
#define CPPJSLIBALL_CPPJSLIBALL_HPP

#ifndef CPPJSLIB_ENABLE_WEBSOCKET
#   define CPPJSLIB_ENABLE_WEBSOCKET
#endif //CPPJSLIB_ENABLE_WEBSOCKET

#ifndef CPPJSLIB_ENABLE_HTTPS
#   define CPPJSLIB_ENABLE_HTTPS
#endif //CPPJSLIB_ENABLE_HTTPS

#include <CppJsLib.hpp>

#ifdef CPPJSLIB_WINDOWS
#   undef strdup
#   undef strcpy
#   undef CPPJSLIB_WINDOWS
#endif //CPPJSLIB_WINDOWS

#ifdef CPPJSLIB_UNIX
#   undef CPPJSLIB_UNIX
#endif //CPPJSLIB_UNIX

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
#   undef CPPHTTPLIB_OPENSSL_SUPPORT
#endif //CPPHTTPLIB_OPENSSL_SUPPORT

#undef CPPJSLIB_MAYBE_UNUSED
#undef CPPJSLIB_NODISCARD

#undef CPPJSLIB_ENABLE_WEBSOCKET
#undef CPPJSLIB_ENABLE_HTTPS

#endif //CPPJSLIBALL_CPPJSLIBALL_HPP
