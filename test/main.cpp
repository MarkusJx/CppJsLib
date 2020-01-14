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
    wGui = new CppJsLib::WebGUI("web");
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