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

## License

This project is licensed under the MIT license. See [LICENSE](LICENSE) for further information.
## Third-Party Licenses

This project uses code from
* [nlohmann/json](https://github.com/nlohmann/json) licensed under [MIT license](https://github.com/nlohmann/json/blob/develop/LICENSE.MIT)
* [yhirose/cpp-httplib](https://github.com/yhirose/cpp-httplib) licensed under [MIT license](https://github.com/yhirose/cpp-httplib/blob/master/LICENSE)
* [openssl/openssl](https://github.com/openssl/openssl) licensed under [Apache License 2.0](https://github.com/openssl/openssl/blob/master/LICENSE)
* [zaphoyd/websocketpp](https://github.com/zaphoyd/websocketpp) license to be seen [here](https://github.com/zaphoyd/websocketpp/blob/master/COPYING)
* [boost](https://www.boost.org) license to be seen [here](https://www.boost.org/users/license.html)
