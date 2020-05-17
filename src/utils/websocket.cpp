/*
 * websocket.cpp
 * Defines functions to utilize the websocket protocol
 *
 * Licensed under the MIT License
 *
 * Copyright (c) 2020 MarkusJx
 *
 * The full license including third-party licenses is available at https://github.com/MarkusJx/CppJsLib/blob/master/LICENSE
 */
#include "websocket.hpp"

#include <random>

#ifdef CPPJSLIB_ENABLE_WEBSOCKET
std::string password;

#   ifdef CPPJSLIB_ENABLE_HTTPS
enum tls_mode {
    MOZILLA_INTERMEDIATE = 1,
    MOZILLA_MODERN = 2
};

std::string get_password() {
    return password;
}

void setPassword() {
    if (password.empty()) {
        std::random_device rd;
        static std::mt19937 eng(rd());
        std::uniform_int_distribution<> d(1, 36);
        const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        for (int i = 0; i < 30; i++) {
            int rnd = d(eng) - 1;
            if (rnd < 10) {
                password.append(std::to_string(rnd));
            } else {
                rnd -= 10;
                password += alphabet[rnd];
            }
        }
    }
}

void on_http(wspp::server_tls *s, websocketpp::connection_hdl hdl) {
    wspp::server_tls::connection_ptr con = s->get_con_from_hdl(std::move(hdl));

    con->set_body("Hello World!");
    con->set_status(websocketpp::http::status_code::ok);
}

wspp::context_ptr on_tls_init(tls_mode mode, const websocketpp::connection_hdl &hdl CPPJSLIB_CERTS) {
    namespace asio = websocketpp::lib::asio;

    loggingF(std::string("using TLS mode: ") + (mode == MOZILLA_MODERN ? "Mozilla Modern" : "Mozilla Intermediate"));
    wspp::context_ptr ctx = websocketpp::lib::make_shared<asio::ssl::context>(asio::ssl::context::sslv23);

    try {
        if (mode == MOZILLA_MODERN) {
            // Modern disables TLSv1
            ctx->set_options(asio::ssl::context::default_workarounds |
                             asio::ssl::context::no_sslv2 |
                             asio::ssl::context::no_sslv3 |
                             asio::ssl::context::no_tlsv1 |
                             asio::ssl::context::single_dh_use);
        } else {
            ctx->set_options(asio::ssl::context::default_workarounds |
                             asio::ssl::context::no_sslv2 |
                             asio::ssl::context::no_sslv3 |
                             asio::ssl::context::single_dh_use);
        }
        ctx->set_password_callback(bind(&get_password));
        ctx->use_certificate_chain_file(cert_path);
        ctx->use_private_key_file(private_key_path, boost::asio::ssl::context::pem);

        std::string ciphers;

        if (mode == MOZILLA_MODERN) {
            ciphers = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK";
        } else {
            ciphers = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA";
        }

        if (SSL_CTX_set_cipher_list(ctx->native_handle(), ciphers.c_str()) != 1) {
            errorF("Error setting cipher list");
        }
    } catch (std::exception &e) {
        errorF(std::string("Exception: ") + e.what());
    }
    return ctx;
}

void initWebsocketTLS(const std::shared_ptr<wspp::server_tls> &s CPPJSLIB_CERTS) {
    try {
        std::function < wspp::context_ptr(tls_mode, websocketpp::connection_hdl) >
        on_tls = [cert_path, private_key_path](tls_mode mode, const websocketpp::connection_hdl &hdl) {
            return on_tls_init(mode, hdl, cert_path, private_key_path);
        };

        s->set_http_handler(bind(&on_http, s.get(), std::placeholders::_1));
        s->set_tls_init_handler(bind(on_tls, MOZILLA_INTERMEDIATE, std::placeholders::_1));
    } catch (websocketpp::exception const &e) {
        errorF(e.what());
    } catch (...) {
        errorF("An unknown exception occurred");
    }
}

#   endif //CPPJSLIB_ENABLE_HTTPS

#   undef CPPJSLIB_CERTS
#endif //CPPJSLIB_ENABLE_WEBSOCKET