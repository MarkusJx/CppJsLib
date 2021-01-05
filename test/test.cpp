#include "CppJsLib.hpp"

std::function<void(bool)> webSetGtaRunning = nullptr;
std::function<void(int)> webSetWinnings = nullptr;
std::function<void(int)> webSetWinningsAll = nullptr;
std::function<void(int)> webSetRacesWon = nullptr;
std::function<void(int)> webSetRacesLost = nullptr;
std::function<void()> webSetStarted = nullptr;
std::function<void()> webSetStopped = nullptr;
std::function<void()> webSetStopping = nullptr;
std::function<void()> webSetStarting = nullptr;
std::function<void(int)> webSetAutostopMoney = nullptr;
std::function<void(int)> webSetAutostopTime = nullptr;

void js_start_script() {}

void js_stop_script() {}

int get_races_won() {
    return 0;
}

int get_races_lost() {
    return 0;
}

int get_all_winnings() {
    return 0;
}

int get_current_winnings() {
    return 0;
}

int get_time() {
    return 0;
}

bool get_gta_running() {
    return false;
}

int get_running() {
    return -1;
}

void set_autostop_money(int) {}

int get_autostop_money() {
    return -1;
}

void set_autostop_time(int) {}

int get_autostop_time() {
    return -1;
}

void callEverything() {
    //try {
        webSetGtaRunning(false);
        webSetWinnings(0);
        webSetWinningsAll(0);
        webSetRacesWon(0);
        webSetRacesLost(0);
        webSetStarted();
        webSetStopped();
        webSetStopping();
        webSetStarting();
        webSetAutostopMoney(-1);
        webSetAutostopTime(-1);
    //} catch (markusjx::cppJsLib::exceptions::CppJsLibException &e) {
    //    std::cout << e.what() << std::endl << e.getStacktrace();
    //}
}

int main() {
    try {
        markusjx::cppJsLib::Server gui("web");
        gui.setLogger([](const std::string &s) {
            std::cout << s << std::endl;
        });

        gui.setError([](const std::string &s) {
            std::cerr << s << std::endl;
        });

        // Expose a lot of functions
        gui.expose(js_start_script);
        gui.expose(js_stop_script);
        gui.expose(get_races_won);
        gui.expose(get_races_lost);
        gui.expose(get_all_winnings);
        gui.expose(get_current_winnings);
        gui.expose(get_time);
        gui.expose(get_gta_running);
        gui.expose(get_running);
        gui.expose(get_autostop_money);
        gui.expose(get_autostop_time);
        gui.expose(set_autostop_time);
        gui.expose(set_autostop_money);
        gui.expose(callEverything);

        // Import some functions
        gui.import(webSetGtaRunning);
        gui.import(webSetWinnings);
        gui.import(webSetWinningsAll);
        gui.import(webSetRacesWon);
        gui.import(webSetRacesLost);
        gui.import(webSetStarted);
        gui.import(webSetStopped);
        gui.import(webSetStopping);
        gui.import(webSetStarting);
        gui.import(webSetAutostopMoney);
        gui.import(webSetAutostopTime);

        gui.start(8027, "localhost", 8028, true);
    } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}