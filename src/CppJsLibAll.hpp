/*
 * CppJsLibAll.hpp
 * Licensed under the MIT License
 *
 * Copyright (c) 2020 MarkusJx
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * The full license including third-party licenses is available at https://github.com/MarkusJx/CppJsLib/blob/master/LICENSE
 *
 * =====================================================================================
 *
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
