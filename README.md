# CppJsLib [![C/C++ Build](https://github.com/MarkusJx/CppJsLib/workflows/C/C++%20CI/badge.svg)](https://github.com/MarkusJx/CppJsLib/actions?query=workflow%3A"C%2FC%2B%2B+CI")

CppJsLib is a C++ library to call C++ function from JavaScript and vice-versa (like [eel](https://github.com/samuelhwilliams/Eel) or [guy](https://github.com/manatlan/guy) for python)


Table of contents
=================

<!--ts-->
   * [Examples](#examples)
     * [Basic example](#basic-example)
     * [JS function with return value](#import-js-function-with-return-value)
     * [SSL/TLS support](#use-with-ssl-enabled)
     * [Start without the http server](#start-without-web-server)
     * [Logging](#logging)
       * [Set logger](#set-logger)
       * [Set error handler](#set-error-message-handler)
     * [Get http server](#get-underlying-yhirosecpp-httplib-server)
     * [Get websocket server](#get-underlying-zaphoydwebsocketpp-websocket-server)
   * [License](#license)
   * [Third-Party licenses](#third-party-licenses)
<!--te-->

# Examples
### Basic example
#### C++ code
```c++
#include <CppJsLib.hpp>

// Use std::function to declare a javascript funtion to be called
std::function<void(int)> jsFunc;

void funcToExpose(int i, std::string s) {
    // Code...
}

int main() {
    using namespace markusjx::cppJsLib;

    Server gui("web");

    // Expose funcToExpose to be called from javascript, use the same name to call it
    gui.expose(funcToExpose);

    // Import function from javascript, function name must be match the js function's name
    gui.import(jsFunc);

    // Call the function from js
    jsFunc(0);

    // Start the web server on port 1234 and the websocket server on port 2345 
    // on the local machine and do not block
    gui.start(1234, 2345, "localhost", false);

    // Stop any servers
    gui.stop();

    return 0;
}
```

#### HTML head
Load CppJsLib.js
```html
<script src="CppJsLib.js"></script>
```

#### Javascript code
```js
cppJsLib.expose(jsFunc);
function jsFunc(i) {
    // Code...
}

cppJsLib.onLoad(function () {
    // Call c++ function after load
    cppJsLib.funcToExpose(0, "some string");
});
```

## Import js function with return value
```c++
// JS functions with return value always return a std::vector with the individual
// responses of all clients
std::function<std::vector<int>()> func;

Server gui("web");

// Import the js function
gui.import(func);

// Start the servers
gui.start(1234, 2345, "localhost", false);

// Call the function
std::vector<int> values = func();

// Do something with the values
for (const auto &i : values) {
    // Code here...
}
```

## Use with SSL enabled
CppJsLib also supports SSL/TLS to make use of the HTTPS protocol. The websocket communication will also be encrypted.
```c++
SSLServer gui("web", "cert.pem", "server.pem");
```

## Start without web server
If you want to provide your own web server (like nginx or the apache web server) you can start the websocket server without starting the web server:
```c++
Server gui;

// Expose functions: gui.expose(...);
// Import functions: gui.import(...);

// Start only the websocket server (non-blocking)
gui.startNoWeb(1234, false);

// Do stuff with it...

// Stop it
gui.stop();
```

You will have to tell CppJsLib.js where to connect to:
```html
<script>
    const CPPJSLIB_NO_INIT = true; // Do not initialize with http server
</script>
<script src="CppJsLib.js"></script>
<script>
    // Initialize with websocket only, no TLS, on localhost and port 1234
    cppJsLib.init(true, false, "localhost", 1234);
</script>
```

## Start without the websocket server
It is also possible to only start the http server. Server sent events will be used for the communication.
Please note that only void JavaScript functions are supported when not relying on the websocket protocol.
```c++
Server srv;

// Expose functions: srv.expose(...);
// Import functions: srv.import(...);

// Start only the websocket server (non-blocking)
srv.startNoWebSocket(1234, false);

// Do stuff with it...

// Stop it
srv.stop();
```

## Logging
### Set logger
```c++
srv.setLogger([] (const std::string &msg) {
    // Do something
});
```

### Set error message handler
```c++
srv.setError([] (const std::string &err) {
    // Do something
});
```

## Get underlying [yhirose/cpp-httplib](https://github.com/yhirose/cpp-httplib) server
### Without SSL
```c++
auto srv = srv.getHttpServer();
```

### With SSL
```c++
auto srv = srv.getHttpsServer();
```

## Get underlying [zaphoyd/websocketpp](https://github.com/zaphoyd/websocketpp) websocket server
### Without SSL
```c++
auto wssrv = srv.getWebServer();
```

### With SSL
```c++
auto wssrv = srv.getTLSWebServer();
```

## License

This project is licensed under the MIT license. See [LICENSE](LICENSE) for further information.
## Third-Party Licenses

This project uses code from
* [nlohmann/json](https://github.com/nlohmann/json) licensed under [MIT license](https://github.com/nlohmann/json/blob/develop/LICENSE.MIT)
* [yhirose/cpp-httplib](https://github.com/yhirose/cpp-httplib) licensed under [MIT license](https://github.com/yhirose/cpp-httplib/blob/master/LICENSE)
* [openssl/openssl](https://github.com/openssl/openssl) licensed under [Apache License 2.0](https://github.com/openssl/openssl/blob/master/LICENSE)
* [boost](https://www.boost.org) licensed under the [Boost Software License](https://www.boost.org/users/license.html)
* [zaphoyd/websocketpp](https://github.com/zaphoyd/websocketpp) license to be seen [here](https://github.com/zaphoyd/websocketpp/blob/master/COPYING)
