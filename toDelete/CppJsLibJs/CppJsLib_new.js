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
    sendHttpRequest: function (type, name, body = null, callback = null) {
        this.serverReachable().then(res => {
            if (!res) {
                console.debug("Disconnected");
                this.onClose();
                return;
            }

            let xhttp = new (window.ActiveXObject || XMLHttpRequest)("Microsoft.XMLHTTP");
            try {
                xhttp.open(type, name, true);
                if (callback != null) {
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
    },
    sendRequest: function (data, callback = null, type = "POST") {
        if (this.webSocket_only) {
            this.callbacks[data.callback] = callback;

            console.debug("Sending request: " + JSON.stringify(data));
            try {
                this.webSocket.send(JSON.stringify(data));
            } catch (error) {
                console.debug("Disconnected");
                this.connected = false;
            }
        } else {
            this.sendHttpRequest(type, "cppjslib", JSON.stringify(data), callback);
        }
    },
    /**
     * Init with a websocket only connection (no web server)
     *
     * @param {String} host the host to connect to
     * @param {Number} port the websocket port
     * @param {Boolean} tls if to use TLS
     */
    initWebsocketOnly: function (host, port, tls = false) {
        this.init(true, tls, host, port);
    },
    onClose: function () {
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
    init: function (websocket_only = false, tls = false, host = "", port = 0) {
        this.webSocket_only = websocket_only;
        this.tls = tls;
        this.host = host;
        this.port = port;
        this.webSocket_only = websocket_only;

        const init_request = () => {
            this.sendHttpRequest("GET", "init", null, response => {
                console.debug("Initializing with sequence: " + response);
                let obj = JSON.parse(response);
                for (let fnName in obj) {
                    this.addFn(fnName, obj[fnName]);
                }

                this.loadFunctions.forEach((fn) => {
                    fn();
                });

                this.initialized = true;
            });
        };

        const ws_onmessage = (event) => {
            console.debug("Received websocket message");
            const data = JSON.parse(event.data);
            if (data.header === "callback") {
                if (this.callbacks.hasOwnProperty(data.callback)) {
                    this.callbacks[data.callback](data.data);
                    this.callbacks.splice(this.callbacks.indexOf(data.callback), 1);
                } else {
                    console.warn("Received data with callback, but this callback does not exist");
                }
            } else if (data.header === "call") {
                const function_name = data.func;

                if (!this.exposedFunctions.hasOwnProperty(function_name)) {
                    console.warn(`C++ tried to call js function ${function_name} which does not exist`);
                    return;
                }

                const toSend = {
                    header: "callback",
                    callback: data.callback,
                    data: null
                };

                if (data.data.length === 1) {
                    if (data.data[0] == null) {
                        toSend.data = this.exposedFunctions[function_name]();
                    } else {
                        toSend.data = this.exposedFunctions[function_name](data.data);
                    }
                } else {
                    toSend.data = this.exposedFunctions[function_name](...data.data);
                }

                if (toSend.data === undefined) toSend.data = null;

                // Let sendRequest handle the sending. Fuck those guys... Wait a second.
                this.sendRequest(toSend);
            }
        };

        if (websocket_only) {
            let wsProtocol = tls ? "wss://" : "ws://";

            console.debug(`Connecting to websocket on: ${wsProtocol}${host}:${port}`);
            this.webSocket = new WebSocket(`${wsProtocol}${host}:${port}`);

            this.webSocket.onerror = () => {
                console.warn("Error in websocket. Closing connection.");
                this.webSocket.close();
            }

            this.connected = true;
            this.webSocket.onclose = this.onClose;

            this.webSocket.onmessage = ws_onmessage;

            this.webSocket.onopen = init_request;
        } else {
            init_request();

            this.sendHttpRequest("GET", "init_ws", null, (response) => {
                let obj = JSON.parse(response);
                console.debug("Initializing webSocket with message: " + response);
                if (obj.ws) {
                    let wsProtocol;
                    if (obj.tls) {
                        wsProtocol = "wss://";
                    } else {
                        wsProtocol = "ws://";
                    }

                    console.debug("Connecting to websocket on: " + wsProtocol + obj.host + ":" + obj.port);
                    this.webSocket = new WebSocket(wsProtocol + obj.host + ":" + obj.port);

                    this.connected = true;
                    this.webSocket.onerror = () => {
                        console.warn("Error in websocket. Closing connection.");
                        this.webSocket.close();
                    }

                    this.connected = true;
                    this.webSocket.onclose = this.onClose;

                    this.webSocket.onmessage = ws_onmessage;
                } else {
                    for (let key in this.exposedFunctions) {
                        const evtSource = new EventSource("cppjslib_events" + key);
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
            });
        }
    },
    generateCallbackId: function () {
        const getId = () => Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
        let rnd = getId();
        while (this.callbacks.hasOwnProperty(rnd)) {
            rnd = getId();
        }

        return rnd;
    },
    addFn: function (name, numArgs) {
        console.debug(`Initializing function ${name} with ${numArgs} argument(s)`);
        this[name] = function () {
            if (numArgs !== arguments.length) {
                throw new Error("Argument count does not match!");
            }

            return new Promise((resolve, reject) => {
                const toSend = {
                    header: `callfunc_${name}`,
                    data: arguments,
                    callback: this.generateCallbackId()
                };

                this.sendRequest(toSend, (res) => {
                    if (res.ok) {
                        resolve(res.data);
                    } else {
                        reject(res.data);
                    }
                });
            });
        }
    },
    expose: function (toExpose) {
        this.exposedFunctions[toExpose.name] = toExpose;
    }
};

if (typeof CPPJSLIB_NO_INIT === "undefined") {
    cppJsLib.init();
} else if (!CPPJSLIB_NO_INIT) {
    cppJsLib.init();
}
