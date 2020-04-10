//
// Created by markus on 22/12/2019.
//

#ifndef CPPJSLIB_STATIC_DEFINE
#   ifdef TEST_ENABLE_WEBSOCKET
#       define CPPJSLIB_ENABLE_WEBSOCKET
#   endif //TEST_ENABLE_WEBSOCKET

#   ifdef TEST_ENABLE_HTTPS
#       define CPPJSLIB_ENABLE_HTTPS
#   endif //TEST_ENABLE_HTTPS
#endif //CPPJSLIB_STATIC_DEFINE

#include <CppJsLib.hpp>
#include <iostream>
#include <thread>

#include <cassert>
#ifdef CPPJSLIB_WINDOWS
#   include <crtdbg.h>

#   define ASSERT_MEM_OK() assert(_CrtCheckMemory())
#else
#   define ASSERT_MEM_OK()
#endif

#include "DifferentWebServer.hpp"

CppJsLib::WebGUI *wGui;
std::function<void(int)> func = {};
std::function<std::vector<int>()> tf = {};

std::function<void()> fn;

void f(int a) {
    printf("Result from function f: %d\n", a);
    func(a);
}

int d() {
    return 0;
}

int main() {
    CppJsLib::setError([](auto s) {
        std::cerr << s << std::endl;
    });

    CppJsLib::setLogger([](auto s) {
        std::cout << s << std::endl;
    });

    ASSERT_MEM_OK();
#ifdef TEST_ENABLE_HTTPS
    std::cout << "Tests were built with HTTPS support enabled" << std::endl;
#   ifdef TEST_USE_DLL
#       ifdef CPPJSLIB_ENABLE_HTTPS
    wGui = CppJsLib::createWebGUI("web", "cert.pem", "server.pem");
#       else
    wGui = CppJsLib::createWebGUI("web");
#       endif
#   else
    wGui = new CppJsLib::WebGUI("web", "cert.pem", "server.pem");
#   endif
#else
#   ifdef TEST_USE_DLL
    wGui = CppJsLib::createWebGUI("web");
#   else
    wGui = new CppJsLib::WebGUI("web");
#   endif
#endif
    ASSERT_MEM_OK();

#ifdef TEST_ENABLE_WEBSOCKET
    wGui->importFunction(fn);
    wGui->importFunction(func);
    wGui->importFunction(tf, 0);
#endif
    wGui->expose(f);
    wGui->expose(d);

    ASSERT_MEM_OK();

    std::cout << "Starting web server..." << std::endl;
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
#   define TEST_WS_PORT 8026,
#else
#   define TEST_WS_PORT
#endif

#ifdef TEST_GHBUILD
    bool block = false;
#else
    bool block = false;
#endif

    ASSERT_MEM_OK();

#ifdef TEST_USE_DLL
    {
        CppJsLib::WebGUI_ptr ptr = CppJsLib::createWebGUI_ptr("web");
        ptr->start(8026, TEST_WS_PORT "localhost", false);
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        ptr->stop();
    }
#endif //TEST_USE_DLL

    ASSERT_MEM_OK();

    DifferentWebServerTest();

    wGui->start(8026, TEST_WS_PORT CppJsLib::localhost, block);

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
    func(5);
#endif

    std::cout << "Stopping web server..." << std::endl;
    if (wGui->stop()) {
        std::cout << "Web server stopped" << std::endl;
    }

#ifdef TEST_USE_DLL
    CppJsLib::deleteWebGUI(wGui);
#else
    delete wGui;
#endif

    ASSERT_MEM_OK();

    return 0;
}
