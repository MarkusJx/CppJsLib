//
// Created by markus on 22/12/2019.
//

#include <CppJsLib.hpp>
#include <iostream>
#include <thread>

CppJsLib::WebGUI *wGui;
CppJsLib::JsFunction<void(int)> *func;

void f(int a) {
    printf("Result from function f: %d\n", a);
    func->operator()(a);
}

int main() {
    wGui = new CppJsLib::WebGUI("web");
    auto fun = wGui->importJsFunction<int>("jsF");
    func = &fun;
    wGui->expose(f);

    std::cout << "Starting web server..." << std::endl;
    wGui->start(8026, "localhost", true);

    std::this_thread::sleep_for(std::chrono::seconds(2));
    std::cout << "Stopping web server..." << std::endl;
    if (CppJsLib::stop(wGui)) {
        std::cout << "Web server stopped" << std::endl;
    }

    return 0;
}