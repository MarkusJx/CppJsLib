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

#ifdef CPPJSLIB_WINDOWS

#   define _CRTDBG_MAP_ALLOC
#   include <cstdlib>
#   include <crtdbg.h>
#   include <cassert>

#   define DUMP_MEM_LEAKS() _CrtDumpMemoryLeaks()
#   define ASSERT_MEM_OK() assert(_CrtCheckMemory())
#else
#   define ASSERT_MEM_OK()
#   define DUMP_MEM_LEAKS()
#endif

#include "DifferentWebServer.hpp"

CppJsLib::WebGUI *wGui;
std::function<void(int)> func = {};
std::function<std::vector<int>()> tf = {};
std::function<void(std::map<int, int>, std::vector<int>)> jsFunc;

std::function<void()> fn;

void f(int a) {
    printf("Result from function f: %d\n", a);
    func(a);
}

std::map<int, std::string> d(const std::map<int, std::string> &v) {
    for (const auto& i : v) {
        std::cout << i.first << ", " << i.second << std::endl;
    }
    return v;
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
    wGui = CppJsLib::WebGUI::create("web");
#       else
    wGui = CppJsLib::WebGUI::create("web");
#       endif
#   else
    wGui = new CppJsLib::WebGUI("web");
    //wGui = new CppJsLib::WebGUI("web", "cert.pem", "server.pem");
#   endif
#else
#   ifdef TEST_USE_DLL
    wGui = CppJsLib::WebGUI::create("web");
#   else
    wGui = new CppJsLib::WebGUI("web");
#   endif
#endif
    ASSERT_MEM_OK();

    wGui->import(fn);
    wGui->import(func);

#ifdef TEST_ENABLE_WEBSOCKET
    wGui->import(tf, 0);
    wGui->import(jsFunc);
#endif
    wGui->expose(f);
    wGui->expose(d);

    ASSERT_MEM_OK();
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
#   define TEST_WS_PORT 8026,
#   define UNIQUE_WS_PORT 8037,
#else
#   define TEST_WS_PORT
#   define UNIQUE_WS_PORT
#endif

#ifdef TEST_GHBUILD
    bool block = false;
#else
    bool block = true;
#endif

    ASSERT_MEM_OK();

#ifdef TEST_USE_DLL
    {
        CppJsLib::WebGUI::WebGUI_unique ptr = CppJsLib::WebGUI::create_unique("web");
        ptr->start(8026, UNIQUE_WS_PORT "localhost", false);
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        ptr->stop();
    }
#endif //TEST_USE_DLL

    ASSERT_MEM_OK();

    DifferentWebServerTest();

    std::cout << "Starting web server..." << std::endl;
    wGui->start(8028, TEST_WS_PORT CppJsLib::localhost, block);

    std::cout << "Sleep" << std::endl;
    //std::this_thread::sleep_for(std::chrono::seconds(20));

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
    func(5);
#endif

    std::cout << "Stopping web server..." << std::endl;
    if (wGui->stop()) {
        std::cout << "Web server stopped" << std::endl;
    }

#ifdef TEST_USE_DLL
    CppJsLib::WebGUI::deleteInstance(wGui);
#else
    delete wGui;
#endif

    ASSERT_MEM_OK();
    DUMP_MEM_LEAKS();
    return 0;
}