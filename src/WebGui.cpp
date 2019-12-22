//
// Created by Markus on 11/12/2019.
//

#include "WebGui.hpp"

using namespace CppJsLib;

WebGUI::WebGUI(const std::string &base_dir) {
    running = false;
    server.set_base_dir(base_dir.c_str());
}

void WebGUI::start(int port, const std::string &host) {
    server.Get("/httpServer.js", [](const httplib::Request &req, httplib::Response &res) {
        std::ifstream inFile;
        inFile.open("httpServerJs/httpServer.js");

        std::stringstream strStream;
        strStream << inFile.rdbuf();
        std::string str = strStream.str();
        inFile.clear();
        inFile.close();
        strStream.clear();

        res.set_content(str, "text/javascript");
        str.clear();
    });

    std::string serialized_string = initList.dump();
    server.Get("/init", [serialized_string](const httplib::Request &req, httplib::Response &res) {
        res.set_content(serialized_string, text);
    });

    if (server.listen(host.c_str(), port)) {
        running = true;
    }
}

httplib::Server *WebGUI::getServer() {
    return &server;
}

WebGUI::~WebGUI() {
    if (running) server.stop();
    for (void *p : funcVector) {
        free(p);
    }
    //Clear the vector and release the memory. Source: https://stackoverflow.com/a/10465032
    std::vector<void *>().swap(funcVector);
}

