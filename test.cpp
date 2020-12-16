#include "CppJsLib.hpp"

std::function<int(int, std::string)> fn;
std::function<void(std::promise<void> &)> d;

int abc(int i) {
    std::cout << "abc called: " << i << std::endl;
    std::thread([i] {
        int x = fn(i, "25");
        std::cout << "a: " << x << std::endl;
    }).detach();
    return i;
}

int main() {
    try {
        markusjx::CppJsLib::Server gui(".");
        gui.setLogger([](const std::string &s) {
            std::cout << s << std::endl;
        });

        gui.setError([](const std::string &s) {
            std::cerr << s << std::endl;
        });

        gui.expose(abc);
        gui.import(fn);
        gui.import(d);

        //gui.start(80, "localhost", 81, true);
        gui.startNoWebSocket(1234);
    } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}