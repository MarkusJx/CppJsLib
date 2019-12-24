//
// Created by markus on 22/12/2019.
//

#include <WebGui.hpp>
#include <variant>

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
    wGui->start(1234);
}