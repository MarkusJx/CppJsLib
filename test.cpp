#include "CppJsLib.hpp"

void abc() {
    return;
}

int main() {
    markusjx::CppJsLib::WebGUI gui("abc");

    gui.expose(abc);
    return 0;
}