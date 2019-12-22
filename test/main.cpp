//
// Created by markus on 22/12/2019.
//

#include <WebGui.hpp>

int main() {
    auto wGui = new CppJsLib::WebGUI("web");
    auto c = wGui->importJsFunction<int, bool>("ab");
    c(0, false);
    wGui->start(1234);
}