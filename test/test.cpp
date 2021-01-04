#include "CppJsLib.hpp"

//std::function<markusjx::cppJsLib::Response<int>(int)> fn;
std::function<void(int)> d;

int abc(int i) {
    std::cout << "abc called: " << i << std::endl;
    return i;
}

int main() {
    //*
    try {
        markusjx::cppJsLib::Server gui(".");
        gui.setLogger([](const std::string &s) {
            std::cout << s << std::endl;
        });

        gui.setError([](const std::string &s) {
            std::cerr << s << std::endl;
        });

        //gui.expose(abc);
        //gui.import(fn);
        gui.import(d);

        gui.start(80, "localhost", 81, false);

        markusjx::cppJsLib::Client cli;
        cli.setLogger([](const std::string &s) {
            std::cout << s << std::endl;
        });

        cli.setError([](const std::string &s) {
            std::cerr << s << std::endl;
        });

        std::function<void(int)> func = [] (int i) {
            std::cout << "abc called: " << i << std::endl;
        };

        cli.exportFunction(func, "d");

        cli.connect("http://localhost:80", false);

        std::this_thread::sleep_for(std::chrono::seconds(3));
        d(5);

        //std::this_thread::sleep_for(std::chrono::seconds(3));
        cli.stop();
        gui.stop();
        //srv.startNoWebSocket(1234);
    } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
    }//*/

    return 0;
}