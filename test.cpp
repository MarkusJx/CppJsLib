#include "CppJsLib.hpp"

std::function<void(int)> fn;

int abc(int i) {
    std::cout << "abc called: " << i << std::endl;
    fn(i);
    return i;
}

int main() {
    try {
        markusjx::CppJsLib::Server gui(".");
        gui.setLogger([] (const std::string &s) {
            std::cout << s << std::endl;
        });

        gui.setError([] (const std::string &s) {
            std::cerr << s << std::endl;
        });

        gui.expose(abc);
        gui.import(fn);

        gui.startBlocking(80, "localhost", 81, true);
    } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}