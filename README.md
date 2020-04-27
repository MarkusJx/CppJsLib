# CppJsLib [![C/C++ Build](https://github.com/MarkusJx/CppJsLib/workflows/C/C++%20CI/badge.svg)](https://github.com/MarkusJx/CppJsLib/actions?query=workflow%3A"C%2FC%2B%2B+CI")

CppJsLib is a C++ library to call C++ function from JavaScript and vice-versa (like [eel](https://github.com/samuelhwilliams/Eel) or [guy](https://github.com/manatlan/guy) for python)

## Examples
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
    using namespace CppJsLib;

    // Create CppJsLib::WebGUI using WebGUI::create (only available when built as dynamic library)
    // Use operator new when not using dynamic library
    WebGUI *gui = WebGUI::create("web");

    // Expose funcToExpose to be called from javascript, use the same name to call it
    gui->expose(funcToExpose);

    // Import function from javascript, function name must be match the js function's name
    gui->import(jsFunc);

    // Call the function from js
    jsFunc(0);

    // Start the web server on port 1234 and the websocket server on port 2345 
    // on the local machine and do not block
    gui->start(1234, 2345, "localhost", false);

    // Stop any servers
    gui->stop();

    // Delete the instance of CppJsLib::WebGUI
    // Use operator delete when not using dynamic library
    WebGUI::deleteInstance(gui);

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
    cppJsLib.funcToExpose(0, "string");
});
```

## Import js function with return value
```c++
// JS functions with return value always return a std::vector with the individual
// responses of all clients
std::function<std::vector<int>()> func;

// Create WebGUI object and use a unique_ptr for automatic memory management
auto gui = WebGUI::create_unique("web");

// Import the js function
gui->import(func);

// Start the servers
gui->start(1234, 2345, "localhost", false);

// Call the function
std::vector<int> values = func();

// Do something with the values
for (const auto &i : values) {
    // Code here...
}

// No need to call delete, the unique_ptr will handle this
```

### Import js function with a timeout
Javascript functions can also be imported with a timout (in seconds) so the function returns after the given amount of time, even if not all clients responded. But the function will return earlier if all clients responded to the function call
```c++
// Import with a timeout of 5 seconds
gui->import(func, 5);
```

## Use with SSL enabled
### Using unique_ptr
```c++
auto gui = WebGUI::create_shared("web", "cert.pem", "server.pem");
```
### Using shared_ptr
```c++
auto gui = WebGUI::create_shared("web", "cert.pem", "server.pem");
```
### Using normal pointers
```c++
auto gui = new WebGUI("web", "cert.pem", "server.pem");
```

## Start without web server
If you want to provide your own web server (like nginx or the apache web server) you can start the websocket server without starting the web server:
```c++
auto gui = WebGUI::create_unique();

// Expose functions: gui->expose(...);
// Import functions: gui->import(...);

// Start only the websocket server (non-blocking)
gui->startNoWeb(1234, false);

// Do stuff with it...

// Stop it
gui->stop();
```

## Usage without relying on the dynamic library

### Create a new instance
```c++
WebGUI *gui = new WebGUI("web");
// or
WebGUI gui("web");
```

### Delete it
```c++
delete gui;
```

## Logging
### Set logger
#### For all future instances
```c++
CppJsLib::setLogger([] (const auto &msg) {
    // Do something
});
```

#### For a specific instance
```c++
gui->setLogger([] (const auto &msg) {
    // Do something
});
```

### Set error message handler
#### For all future versions
```c++
CppJsLib::setError([] (const auto &err) {
    // Do something
});
```

#### For a specific instance
```c++
gui->setError([] (const auto &err) {
    // Do something
});
```

## Get underlying [yhirose/cpp-httplib](https://github.com/yhirose/cpp-httplib) server
### Without SSL
```c++
auto srv = gui->getHttpServer();
```

### With SSL
```c++
auto srv = gui->getHttpsServer();
```

## Get underlying [zaphoyd/websocketpp](https://github.com/zaphoyd/websocketpp) websocket server
### Without SSL
```c++
auto wssrv = gui->getWebServer();
```

### With SSL
```c++
auto wssrv = gui->getTLSWebServer();
```

## Adding it to your project
### Using prebuilt binaries
* You can download the latest artifact on [GitHub Actions](https://github.com/MarkusJx/CppJsLib/actions?query=workflow%3A"C%2FC%2B%2B+CI")
* Add ```CppJsLib.hpp``` to your include path
* Add openssl libraries (windows version can be found [here](https://www.npcglib.org/~stathis/blog/precompiled-openssl)), the CppJsLib library and ```CppJsLibJs/CppJsLib.js``` to the output folder
* Link against ``CppJsLib``
* Define macros before including ``CppJsLib.hpp``:
```c++
#define CPPJSLIB_ENABLE_WEBSOCKET
#define CPPJSLIB_ENABLE_HTTPS

#include <CppJsLib.hpp>
```
* Put the ``CppJsLibJs`` folder with the ``CppJsLib.js`` file inside of it into your Application's folder

### Not using prebuilt binaries
Also known as 'building yourself' or 'the not fun way'
* To build with websocket protocol support, boost >= 1.60 < 1.70 must be installed (on windows the environment variable ``BOOST_ROOT`` must point to where the boost installation is located)
* To build with SSL support OpenSSL must be installed
* CMake is used to build the project
* Add ``InitCppJsLib.cmake`` to where your ``CMakeLists.txt`` is located
* Add following lines to the end of your ``CMakeLists.txt``:
```cmake
include(InitCppJsLib.cmake)

initCppJsLib(<your-project> ${CMAKE_SOURCE_DIR}/<source-folder> ${CMAKE_SOURCE_DIR}/<include-folder>)
```
* The following CMake flags can be used to enable different options:
```
ENABLE_WEBSOCKET: Enable websocket protocol support (Boost required)
ENABLE_HTTPS: Enable HTTPS support (OpenSSL required)
USE_JUTILS: Use a dll built with GraalVM to use Java to check if a port is in use
BUILD_JNI_DLL: Build a dll to be called with JNI
```
* Put the ``CppJsLibJs`` folder with the ``CppJsLib.js`` file inside of it into your Application's folder

## Java binding
### Basic example
```java
private static void fn1(int i) {
    // Code
}

private static int fn2(String s) {
    // Code
}

public static void main(String[] args) {
    // Create instance of WebGUI
    WebGUI gui = new WebGUI("web");

    // Expose void function, cast types to the required type,
    // set the function name and the argument types
    gui.exposeVoidFunction(types -> fn1((int) types[0]), "fn1", int.class);

    // Expose non-void function, cast types, set the function name,
    // the return type and the argument types
    gui.exposeFunction(types -> fn2((String) types[0]), "fn2", int.class, String.class);

    // Import javascript void function with name and argument types
    JavaScriptVoidFunc fn = gui.importVoidFunction("func", int.class);

    // Call JavaScript function
    fn.call(0);

    // Import non-void function with name, a timeout, -1 equals infinite,
    // the return type and the argument types
    JavaScriptFunc<Integer> f = gui.importFunction("f", -1, int.class, int.class);

    // Start the servers with their ports on this machine, without blocking
    gui.start(8025, 8026, "localhost", false);
        
    // Stop the servers
    gui.stop();
}
```

## License

This project is licensed under the MIT license. See [LICENSE](LICENSE) for further information.
## Third-Party Licenses

This project uses code from
* [nlohmann/json](https://github.com/nlohmann/json) licensed under [MIT license](https://github.com/nlohmann/json/blob/develop/LICENSE.MIT)
* [yhirose/cpp-httplib](https://github.com/yhirose/cpp-httplib) licensed under [MIT license](https://github.com/yhirose/cpp-httplib/blob/master/LICENSE)
* [openssl/openssl](https://github.com/openssl/openssl) licensed under [Apache License 2.0](https://github.com/openssl/openssl/blob/master/LICENSE)
* [zaphoyd/websocketpp](https://github.com/zaphoyd/websocketpp) license to be seen [here](https://github.com/zaphoyd/websocketpp/blob/master/COPYING)
* [boost](https://www.boost.org) license to be seen [here](https://www.boost.org/users/license.html)
