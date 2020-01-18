//
// Created by markus on 22/12/2019.
//

#include <CppJsLib.hpp>
#include <iostream>
#include <thread>

CppJsLib::WebGUI *wGui;
std::function<void(int)> func = {};

void f(int a) {
    printf("Result from function f: %d\n", a);
    func(a);
}

int main() {
    CppJsLib::setError([](auto s) {
        std::cerr << s << std::endl;
    });

    CppJsLib::setLogger([](auto s) {
        std::cout << s << std::endl;
    });

#ifdef TEST_ENABLE_HTTPS
    std::cout << "Test were built with HTTPS support enabled" << std::endl;
    wGui = new CppJsLib::WebGUI("web", true, "", "");
#else
    wGui = new CppJsLib::WebGUI("web");
#endif

    wGui->importFunction(&func);
    wGui->expose(f);

    std::cout << "Starting web server..." << std::endl;
    wGui->start(8026, "localhost", false);

    std::this_thread::sleep_for(std::chrono::seconds(2));
    std::cout << "Stopping web server..." << std::endl;
    if (CppJsLib::stop(wGui)) {
        std::cout << "Web server stopped" << std::endl;
    }

    delete wGui;

    return 0;
}