//
// Created by markus on 02/03/2020.
//

#ifndef CPPJSLIBALL_WEBSOCKET_HPP
#define CPPJSLIBALL_WEBSOCKET_HPP

#include "../CppJsLib.hpp"
#include "loggingfunc.hpp"

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
#   ifdef CPPJSLIB_ENABLE_HTTPS
#       define CPPJSLIB_CERTS , const std::string &cert_path, const std::string &private_key_path
#   else
#       define CPPJSLIB_CERTS
#   endif //CPPJSLIB_ENABLE_HTTPS

#   include <set>
#   include <websocketpp/server.hpp>

#   ifdef CPPJSLIB_ENABLE_HTTPS

#       include <websocketpp/config/asio.hpp>

namespace wspp {
    typedef websocketpp::server<websocketpp::config::asio> server;
    typedef websocketpp::server<websocketpp::config::asio_tls> server_tls;
    typedef websocketpp::lib::shared_ptr<websocketpp::lib::asio::ssl::context> context_ptr;
}

void initWebsocketTLS(const std::shared_ptr<wspp::server_tls> &s CPPJSLIB_CERTS);

#   else
#       include <websocketpp/config/asio_no_tls.hpp>
namespace wspp {
    typedef websocketpp::server<websocketpp::config::asio> server;
}
#   endif //CPPJSLIB_ENABLE_HTTPS

namespace wspp {
    typedef std::set<websocketpp::connection_hdl, std::owner_less<websocketpp::connection_hdl>> con_list;
}

using websocketpp::lib::bind;

#ifdef CPPJSLIB_ENABLE_HTTPS
void setPassword();
#endif

template<typename EndpointType>
inline void initWebsocketServer(std::shared_ptr<EndpointType> s, const std::shared_ptr<wspp::con_list> &list) {
    try {
        s->set_open_handler(bind([list](const websocketpp::connection_hdl &hdl) {
            list->insert(hdl);
        }, std::placeholders::_1));
        s->set_close_handler(bind([list](const websocketpp::connection_hdl &hdl) {
            list->erase(hdl);
        }, std::placeholders::_1));

        s->set_access_channels(websocketpp::log::alevel::all);
        s->clear_access_channels(websocketpp::log::alevel::frame_payload);

        s->init_asio();
    } catch (websocketpp::exception const &e) {
        errorF(e.what());
    } catch (...) {
        errorF("An unknown exception occurred");
    }
}

template<typename EndpointType>
inline void startWebsocketServer(std::shared_ptr<EndpointType> s, int port) {
    s->listen(port);
    s->start_accept();

    s->run();
}

#endif

#endif //CPPJSLIBALL_WEBSOCKET_HPP
