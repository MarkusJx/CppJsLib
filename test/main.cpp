//
// Created by markus on 22/12/2019.
//

#ifdef TEST_ENABLE_WEBSOCKET
#   define CPPJSLIB_ENABLE_WEBSOCKET
#endif

#ifdef TEST_ENABLE_HTTPS
#   define CPPJSLIB_ENABLE_HTTPS
#endif

#include <CppJsLib.hpp>
#include <iostream>
#include <thread>
#include <atomic>

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

#ifdef TEST_ENABLE_HTTPS
    std::cout << "Tests were built with HTTPS support enabled" << std::endl;
    wGui = new CppJsLib::WebGUI("web", "cert.pem", "server.pem");
#else
    wGui = new CppJsLib::WebGUI("web");
#endif

    void (*a) (int);
    a = {

    };

#ifdef TEST_ENABLE_WEBSOCKET
    wGui->importFunction(&fn);
    wGui->importFunction(&func);
    wGui->importFunction(&tf, 0);
#endif
    wGui->expose(f);
    wGui->expose(d);

    std::cout << "Starting web server..." << std::endl;
#ifdef TEST_ENABLE_WEBSOCKET
#   define TEST_WS_PORT 8026,
#else
#   define TEST_WS_PORT
#endif

#ifdef TEST_GHBUILD
    bool block = false;
#else
    bool block = false;
#endif
    wGui->start(8026, TEST_WS_PORT "127.0.0.1", block);

    std::this_thread::sleep_for(std::chrono::seconds(2));
    std::cout << "Stopping web server..." << std::endl;
    if (CppJsLib::stop(wGui)) {
        std::cout << "Web server stopped" << std::endl;
    }

    delete wGui;

    return 0;
}