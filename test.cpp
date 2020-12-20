#include "CppJsLib.hpp"

std::function<markusjx::cppJsLib::Response<int>(int)> fn;
std::function<void(std::promise<void> &)> d;

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

        gui.expose(abc);
        gui.import(fn);
        gui.import(d);

        std::thread([] {
            try {
                std::this_thread::sleep_for(std::chrono::seconds(30));
                markusjx::cppJsLib::Response<int> res = fn(5);
                res.wait();
                std::cout << res.size() << std::endl;

                for (int i : res) {
                    std::cout << i << std::endl;
                }
            } catch (const std::exception &e) {
                std::cerr << e.what() << std::endl;
            }
        }).detach();

        gui.start(80, "localhost", 81, true);
        //srv.startNoWebSocket(1234);
    } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
    }//*/

    return 0;
}