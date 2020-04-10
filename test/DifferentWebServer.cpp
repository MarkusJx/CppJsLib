//
// Created by markus on 10/04/2020.
//

#ifndef CPPJSLIB_STATIC_DEFINE
#   ifdef TEST_ENABLE_WEBSOCKET
#       define CPPJSLIB_ENABLE_WEBSOCKET
#   endif //TEST_ENABLE_WEBSOCKET

#   ifdef TEST_ENABLE_HTTPS
#       define CPPJSLIB_ENABLE_HTTPS
#   endif //TEST_ENABLE_HTTPS
#endif //CPPJSLIB_STATIC_DEFINE

#include "DifferentWebServer.hpp"
#include <CppJsLib.hpp>
#include <thread>

int webSocketOnlyTest(int n) {
    return n * n;
}

void DifferentWebServerTest() {
#ifdef CPPJSLIB_ENABLE_WEBSOCKET
#   ifdef TEST_USE_DLL
    auto srv = CppJsLib::createWebGUI_ptr("WebSocketOnly");
    auto ptr = CppJsLib::createWebGUI_ptr("");
#   else
    auto srv = std::make_unique<CppJsLib::WebGUI>("WebSocketOnly");
    auto ptr = std::make_unique<CppJsLib::WebGUI>("");
#   endif
    std::cout << "Starting html server" << std::endl;
    srv->check_ports = false;
    srv->start(80, 81, "localhost", false);

    ptr->expose(webSocketOnlyTest);
    std::cout << "Starting websocket server" << std::endl;
    ptr->check_ports = false;
    ptr->startNoWeb(8025, true);
    std::this_thread::sleep_for(std::chrono::minutes(1));

    std::cout << "Stopping servers" << std::endl;
    ptr->stop();
    srv->stop();
#endif
}