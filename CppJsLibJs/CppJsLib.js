/*
 * CppJsLib.js
 * 
 * Licensed under the MIT License
 *
 * Copyright (c) 2020 MarkusJx
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * The full license including third-party licenses is available at https://github.com/MarkusJx/CppJsLib/blob/master/LICENSE
 */
const cppJsLib = {
    /**
     * @type [function]
     */
    'loadFunctions': [],
    'initialized': false,
    'exposedFunctions': [],
    'connected': false,
    'webSocket_only': false,
    'callbacks': [],
    'websocket_only': false,
    'tls': false,
    'host': "",
    'port': 0,
    'disconnectTimeoutRunning': false,
    /**
     * @type WebSocket
     */
    'webSocket': null,
    'onLoad': function (fn) {
        if (typeof fn !== 'function') {
            console.error("Function added to onLoad is not a function");
            return;
        }
        if (!this.initialized) {
            this.loadFunctions.push(fn);
        } else {
            fn();
        }
    },
    /**
     * Check if the server is reachable
     * Source: https://gist.github.com/gitawego/4250714
     *
     * @returns {Promise<Boolean>} if the server is reachable
     */
    'serverReachable': function () {
        // IE vs. standard XHR creation
        let x = new (window.ActiveXObject || XMLHttpRequest)("Microsoft.XMLHTTP"),
            s;
        let port = "";
        if (location.port.length > 0) {
            port = ":" + location.port;
        }
        return new Promise(resolve => {
            if (typeof CPPJSLIB_NO_CONNECTED_CHECK != "undefined" && CPPJSLIB_NO_CONNECTED_CHECK) {
                resolve(true);
            } else {
                x.open(
                    // requesting the headers is faster, and just enough
                    "HEAD",
                    // append a random string to the current hostname,
                    // to make sure we're not hitting the cache
                    "//" + window.location.hostname + port + "/?rand=" + Math.random(),
                    // make a synchronous request
                    true
                );
                try {
                    x.send();
                    x.onreadystatechange = () => {
                        s = x.status;
                        resolve(s >= 200 && s < 300 || s === 304);
                    }
                    // catch network & other problems
                } catch (e) {
                    resolve(false);
                }
            }
        });
    },
    'sendRequest': function (request, callback = false, body = "", type = "POST") {
        if (this.webSocket_only) {
            let req = {};
            req["header"] = request;
            req["data"] = body;
            if (callback) {
                let rnd = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
                while (this.callbacks.hasOwnProperty(rnd)) {
                    rnd = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
                }

                this.callbacks[rnd] = callback;
                req["callback"] = rnd;
            }

            console.debug("Sending request: " + JSON.stringify(req));
            try {
                this.webSocket.send(JSON.stringify(req));
            } catch (error) {
                console.debug("Disconnected");
                this.connected = false;
            }
        } else {
            this.serverReachable().then(res => {
                if (!res) {
                    console.debug("Disconnected");
                    this.onClose();
                    return;
                }

                let xhttp = new (window.ActiveXObject || XMLHttpRequest)("Microsoft.XMLHTTP");
                try {
                    xhttp.open(type, request, true);
                    if (callback) {
                        xhttp.onreadystatechange = function () {
                            if (this.readyState === 4 && this.status === 200) {
                                callback(xhttp.responseText);
                            }
                        };
                    }
                    xhttp.send(body);
                } catch (error) {
                    console.debug("Disconnected");
                    this.connected = false;
                }
            });
        }
    },
    /**
     * Init with a websocket only connection (no web server)
     *
     * @param {String} host the host to connect to
     * @param {Number} port the websocket port
     * @param {Boolean} tls if to use TLS
     */
    'initWebsocketOnly': function (host, port, tls = false) {
        this.init(true, tls, host, port);
    },
    'onClose': function () {
        if (!this.disconnectTimeoutRunning) {
            this.disconnectTimeoutRunning = true;
            this.connected = false;
            console.debug("Connection closed. Trying to reconnect in 5 seconds");
            setTimeout(() => {
                cppJsLib.disconnectTimeoutRunning = false;
                cppJsLib.init(this.websocket_only, this.tls, this.host, this.port);
            }, 5000);
        }
    },
    'init': function (websocket_only = false, tls = false, host = "", port = 0) {
        this.webSocket_only = websocket_only;
        this.tls = tls;
        this.host = host;
        this.port = port;
        if (websocket_only) {
            this.webSocket_only = true;
            let wsProtocol;
            if (tls) {
                wsProtocol = "wss://";
            } else {
                wsProtocol = "ws://";
            }

            console.debug("Connecting to websocket on: " + wsProtocol + host + ":" + port);
            this.webSocket = new WebSocket(wsProtocol + host + ":" + port);

            this.webSocket.onerror = () => {
                console.warn("Error in websocket. Closing connection.");
                this.webSocket.close();
            }

            this.connected = true;
            this.webSocket.onclose = this.onClose;

            this.webSocket.onmessage = (event) => {
                console.debug("Received websocket message");
                let data = JSON.parse(event.data);
                if (data.hasOwnProperty("callback") && data.hasOwnProperty("data")) {
                    if (this.callbacks.hasOwnProperty(data["callback"])) {
                        this.callbacks[data["callback"]](data["data"]);
                    } else {
                        console.warn("Received data with callback, but this callback does not exist");
                    }
                } else {
                    let key = Object.keys(data)[0];

                    if (!this.exposedFunctions.hasOwnProperty(key)) {
                        console.warn("C++ tried to call js function " + key + " which does not exist");
                        return;
                    }

                    if (data[key].length === 1) {
                        if (data[key][0] === "") {
                            this.exposedFunctions[key]();
                        } else {
                            this.exposedFunctions[key](JSON.parse(data[key]));
                        }
                    } else {
                        this.exposedFunctions[key](...JSON.parse(data[key]));
                    }
                }
            };

            this.webSocket.onopen = () => {
                console.debug("Connected to websocket");
                this.sendRequest("init", (response) => {
                    console.debug("Initializing with sequence: " + response);
                    let obj = JSON.parse(response);
                    for (let fnName in obj) {
                        if (obj.hasOwnProperty(fnName)) {
                            let args = obj[fnName].toString().split("(");
                            let returnType = args[0].split(" ")[0];
                            args = args[1].replace(")", "").trim().split(", ");
                            if (args[0] === "" && args.length === 1) {
                                args = [];
                            }
                            this.addFn(returnType, fnName, args);
                        }
                    }

                    this.loadFunctions.forEach((fn) => {
                        fn();
                    });

                    this.initialized = true;
                });
            };
        } else {
            this.sendRequest("init", (response) => {
                console.debug("Initializing with sequence: " + response);
                let obj = JSON.parse(response);
                for (let fnName in obj) {
                    if (obj.hasOwnProperty(fnName)) {
                        let args = obj[fnName].toString().split("(");
                        let returnType = args[0].split(" ")[0];
                        args = args[1].replace(")", "").trim().split(", ");
                        if (args[0] === "" && args.length === 1) {
                            args = [];
                        }
                        this.addFn(returnType, fnName, args);
                    }
                }

                this.loadFunctions.forEach((fn) => {
                    fn();
                });

                this.initialized = true;
            }, "", "GET");

            this.sendRequest("init_ws", (response) => {
                let obj = JSON.parse(response);
                console.debug("Initializing webSocket with message: " + response);
                if (obj["ws"] === "true") {
                    let wsProtocol;
                    if (obj["tls"] === "true") {
                        wsProtocol = "wss://";
                    } else {
                        wsProtocol = "ws://";
                    }

                    console.debug("Connecting to websocket on: " + wsProtocol + obj["host"] + ":" + obj["port"]);
                    this.webSocket = new WebSocket(wsProtocol + obj["host"] + ":" + obj["port"]);

                    this.connected = true;
                    this.webSocket.onerror = () => {
                        console.warn("Error in websocket. Closing connection.");
                        this.webSocket.close();
                    }

                    this.connected = true;
                    this.webSocket.onclose = this.onClose;

                    this.webSocket.onmessage = (event) => {
                        let data = JSON.parse(event.data);
                        let key = Object.keys(data)[0];

                        if (!this.exposedFunctions.hasOwnProperty(key)) {
                            console.warn("C++ tried to call js function " + key + " which does not exist");
                            return;
                        }

                        if (data[key].length === 1) {
                            if (data[key][0] === "") {
                                if (data.hasOwnProperty("callback")) {
                                    let toSend = {};
                                    toSend["header"] = "callback";
                                    toSend["callback"] = data["callback"];
                                    toSend["data"] = String(this.exposedFunctions[key]());
                                    try {
                                        this.webSocket.send(JSON.stringify(toSend));
                                    } catch (error) {
                                        console.error("Could not send data");
                                    }
                                } else {
                                    this.exposedFunctions[key]();
                                }
                            } else {
                                if (data.hasOwnProperty("callback")) {
                                    let toSend = {};
                                    toSend["header"] = "callback";
                                    toSend["callback"] = data["callback"];
                                    toSend["data"] = String(this.exposedFunctions[key](JSON.parse(data[key])));
                                    try {
                                        this.webSocket.send(JSON.stringify(toSend));
                                    } catch (error) {
                                        console.error("Could not send data");
                                    }
                                } else {
                                    this.exposedFunctions[key](JSON.parse(data[key]));
                                }
                            }
                        } else {
                            if (data.hasOwnProperty("callback")) {
                                let toSend = {};
                                toSend["header"] = "callback";
                                toSend["callback"] = data["callback"];
                                toSend["data"] = String(this.exposedFunctions[key](...JSON.parse(data[key])));
                                try {
                                    this.webSocket.send(JSON.stringify(toSend));
                                } catch (error) {
                                    console.error("Could not send data");
                                }
                            } else {
                                this.exposedFunctions[key](...JSON.parse(data[key]));
                            }
                        }
                    }
                } else {
                    for (let key in this.exposedFunctions) {
                        const evtSource = new EventSource("ev_" + key);
                        evtSource.onopen = () => {
                            console.debug("Listening for Server Sent Event: ev_" + key);
                        }

                        evtSource.onclose = () => {
                            console.debug("SSE connection closed")
                        }

                        evtSource.onmessage = (event) => {
                            console.debug("Received sse event message: " + event.data);
                            let data = JSON.parse(event.data);
                            let key = Object.keys(data)[0];
                            if (this.exposedFunctions.hasOwnProperty(key)) {
                                if (data[key].length === 1) {
                                    if (data[key][0] === "") {
                                        this.exposedFunctions[key]();
                                    } else {
                                        this.exposedFunctions[key](JSON.parse(data[key]));
                                    }
                                } else {
                                    this.exposedFunctions[key](...JSON.parse(data[key]));
                                }
                            }
                        }
                    }
                    this.connected = true;
                }
            }, "", "GET");
        }
    },
    'addFn': function (returnType, name, args) {
        console.debug("Initializing function " + name + " with " + args.length + " argument(s): " + args);
        this[name] = function () {
            if (args.length !== arguments.length) {
                console.error("Argument count does not match!");
                return;
            }

            for (let i = 0; i < args.length; i++) {
                if (!this.argMatches(arguments[i], args[i])) {
                    console.error("Arguments do not match!\n Expected: " + args[i] + " but got: " +
                        ((Array.isArray(arguments[i]) && arguments[i].length > 0) ? typeof (arguments[i][0]) + "[]" : typeof (arguments[i])));
                    return;
                }
            }

            let obj = {args: arguments};

            if (returnType !== "void") {
                return new Promise((resolve) => {
                    this.sendRequest("callfunc_" + name, (res) => {
                        if (returnType === "bool") {
                            if (typeof res === "string" && res.startsWith("\"")) {
                                res = JSON.parse(res);
                            }
                            res = (res === "1");
                        }

                        try {
                            resolve(JSON.parse(res));
                        } catch (error) {
                            console.warn("Could not parse JSON, passing string");
                            resolve(res);
                        }
                    }, JSON.stringify(obj));
                });
            } else {
                this.sendRequest("callfunc_" + name, false, JSON.stringify(obj));
            }
        }
    },
    'argMatches': function (arg, argString) {
        if (argString.endsWith("[]")) {
            if (Array.isArray(arg)) {
                if (arg.length > 0) {
                    return this.argMatches(arg[0], argString.replace("[]", ""));
                } else {
                    return true;
                }
            } else {
                return false;
            }
        }

        if (argString.startsWith("map<")) {
            if (typeof (arg) === "object") {
                try {
                    argString = argString.replace("map<", "").replace(">", "").split(",");
                    if (Object.entries(arg).length > 0) {
                        let k = Object.keys(arg)[0];
                        return this.argMatches(arg[k], argString[1]);
                    } else {
                        return true;
                    }
                } catch (e) {
                    return false;
                }
            } else {
                return false;
            }
        }

        switch (argString) {
            case "int":
                return typeof (arg) === "number";
            case "bool":
                return typeof (arg) === "boolean";
            case "float":
                return typeof (arg) === "number";
            case "double":
                return typeof (arg) === "number";
            case "string":
                return typeof (arg) === "string";
            default:
                return false;
        }
    },
    'expose': function (toExpose) {
        this.exposedFunctions[toExpose.name] = toExpose;
    }
};

if (typeof CPPJSLIB_NO_INIT === "undefined") {
    cppJsLib.init();
} else if (!CPPJSLIB_NO_INIT) {
    cppJsLib.init();
}
