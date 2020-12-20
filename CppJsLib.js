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
    loadFunctions: [],
    /**
     * @type [function]
     */
    disconnectListeners: [],
    /**
     * @type [function]
     */
    connectListeners: [],
    initialized: false,
    exposedFunctions: [],
    connected: false,
    webSocket_only: false,
    callbacks: [],
    websocket_only: false,
    tls: false,
    host: "",
    port: 0,
    disconnectTimeoutRunning: false,
    disconnectTimeoutSeconds: 10,
    /**
     * The websocket object
     * @type WebSocket | null
     */
    webSocket: null,
    /**
     * The sse event source
     * @type EventSource | null
     */
    eventSource: null,
    /**
     * Listen for an event. Current events are 'loaded' and 'disconnected'
     *
     * @param {string} event the event name
     * @param {function(): void} fn the listener
     */
    listen: function (event, fn) {
        if (typeof fn !== 'function') {
            throw new Error("Argument at position 1 is not a function");
        }

        switch (event) {
            case "loaded":
                if (!this.initialized) {
                    this.loadFunctions.push(fn);
                } else {
                    fn();
                }
                break;
            case "disconnected":
                this.disconnectListeners.push(fn);
                if (!this.connected) {
                    fn();
                }
                break;
            case "connected":
                this.connectListeners.push(fn);
                if (this.connected) {
                    fn();
                }
                break;
            default:
                throw new Error(`The event with name ${event} does not exist`);
        }
    },
    /**
     * Unlisten from an event
     *
     * @param {string} event the event name
     * @param {function(): void} fn the listener to remove
     */
    unlisten(event, fn) {
        if (typeof fn !== 'function') {
            throw new Error("Argument at position 1 is not a function");
        }

        switch (event) {
            case "loaded":
                this.loadFunctions.splice(this.loadFunctions.indexOf(fn), 1);
                break;
            case "disconnected":
                this.disconnectListeners.splice(this.disconnectListeners.indexOf(fn), 1);
                break;
            case "connected":
                this.connectListeners.splice(this.connectListeners.indexOf(fn), 1);
                break;
            default:
                throw new Error(`The event with name ${event} does not exist`);
        }
    },
    /**
     * Check if the server is reachable
     * Source: https://gist.github.com/gitawego/4250714
     *
     * @returns {Promise<Boolean>} if the server is reachable
     */
    serverReachable: function () {
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
    /**
     * A callback for requests
     * @callback requestCallback
     * @param {string} val the request result
     * @returns {void}
     */

    /**
     * Send a http request
     *
     * @param {string} type the request type. May be "GET" or "POST"
     * @param {string} name the path of the request
     * @param {string | null} body the string to send or null
     * @param {requestCallback | null} callback a callback function or null
     */
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
                            console.log(xhttp.responseText);
                            callback(xhttp.responseText);
                        }
                    };
                }
                xhttp.send(body);
            } catch (error) {
                console.debug("Disconnected");
                this.onClose();
            }
        });
    },
    /**
     * Send a request either via http or websocket.
     *
     * @param {Object} data the data to send
     * @param {requestCallback} callback the callback function
     * @param {string} type the http request type. May be "GET" or "POST"
     */
    sendRequest: function (data, callback = null, type = "POST") {
        if (this.webSocket_only) {
            this.callbacks[data.callback] = callback;

            console.debug("Sending request: " + JSON.stringify(data));
            try {
                this.webSocket.send(JSON.stringify(data));
            } catch (error) {
                console.debug("Disconnected");
                this.onClose();
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
            if (this.connected) this.disconnectListeners.forEach(fn => fn());
            this.disconnectTimeoutRunning = true;
            this.connected = false;
            console.debug(`Connection closed. Trying to reconnect in ${this.disconnectTimeoutSeconds} seconds`);
            setTimeout(() => {
                cppJsLib.disconnectTimeoutRunning = false;
                cppJsLib.init(this.websocket_only, this.tls, this.host, this.port);
            }, this.disconnectTimeoutSeconds * 1000);
        }
    },
    /**
     * Initialize CppJsLibJs. All the option are only to be set when websocket_only == true.
     * If it is set to false, the configuration is automatically retrieved from the server.
     *
     * @param {boolean} websocket_only whether this is websocket only
     * @param {boolean} tls whether to use tls (when websocket_only == true, otherwise this will be set automatically)
     * @param {string} host the host address
     * @param {number} port the host port
     */
    init: function (websocket_only = false, tls = false, host = "", port = 0) {
        this.webSocket_only = websocket_only;
        this.tls = tls;
        this.host = host;
        this.port = port;
        this.webSocket_only = websocket_only;

        // The init request to be called to get the exported functions
        const init_request = () => {
            // The callback function, which sets the exported functions
            const callback_fn = response => {
                console.debug("Initializing with sequence: " + response);
                let obj = JSON.parse(response);
                for (let fnName in obj) {
                    this.addFn(fnName, obj[fnName]);
                }

                this.loadFunctions.forEach(fn => fn());
                this.initialized = true;
            };

            // When websocket_only is set, send the request via websocket,
            // if not, send the data as a GET request via http
            if (!websocket_only) {
                this.sendHttpRequest("GET", "init", null, callback_fn);
            } else {
                const data = {
                    header: "init",
                    callback: this.generateCallbackId()
                };
                this.sendRequest(data, callback_fn);
            }
        };

        // The main message parser
        const ws_onmessage = (event) => {
            console.log("Abcdef");
            console.debug("Received websocket message: " + event.data);
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
                    this.sendRequest({
                        header: "callback",
                        callback: data.callback,
                        ok: false,
                        data: `The function with name ${function_name} is not exported`
                    });
                    return;
                }

                const toSend = {
                    header: "callback",
                    callback: data.callback,
                    ok: true,
                    data: null
                };

                try {
                    if (data.data.length === 1) {
                        if (data.data[0] == null) {
                            toSend.data = this.exposedFunctions[function_name]();
                        } else {
                            toSend.data = this.exposedFunctions[function_name](data.data[0]);
                        }
                    } else {
                        toSend.data = this.exposedFunctions[function_name](...data.data);
                    }
                } catch (e) {
                    toSend.ok = false;
                    toSend.data = e.message;
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
                if (obj["ws"] === true) {
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

                    this.webSocket.onopen = () => {
                        console.debug("Connected to the websocket server");
                    };

                    this.connected = true;
                    this.webSocket.onclose = this.onClose;

                    this.webSocket.onmessage = ws_onmessage;
                } else {
                    this.eventSource = new EventSource("cppjslib_events");
                    this.eventSource.onopen = () => {
                        console.debug("Listening for Server Sent Event: cppjslib_events");
                        this.connected = true;
                    }

                    this.eventSource.onclose = () => {
                        console.debug("SSE connection closed")
                        this.onClose();
                    }

                    this.eventSource.onerror = () => {
                        console.debug("SSE connection error, closing connection");
                        this.onClose();
                        this.eventSource.close();
                    };

                    this.eventSource.onmessage = ws_onmessage;
                }
            });
        }
    },
    /**
     * Generate a callback id
     *
     * @returns {string} a random callback id
     */
    generateCallbackId: function () {
        const getId = () => Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
        let rnd = getId();
        while (this.callbacks.hasOwnProperty(rnd)) {
            rnd = getId();
        }

        return rnd;
    },
    /**
     * Add a c++ exported function to this. Will be called by init.
     *
     * @param {string} name the function name to import
     * @param {number} numArgs the number of arguments the function expects
     */
    addFn: function (name, numArgs) {
        console.debug(`Initializing function ${name} with ${numArgs} argument(s)`);
        this[name] = function (...args) {
            if (numArgs !== arguments.length) {
                throw new Error(`Argument count does not match. Expected: ${numArgs} vs. got: ${arguments.length}`);
            }

            return new Promise((resolve, reject) => {
                console.debug(`Calling function with args: ${args}`);
                const toSend = {
                    header: "call",
                    func: name,
                    data: args,
                    callback: this.generateCallbackId()
                };

                this.sendRequest(toSend, (res) => {
                    res = JSON.parse(res);
                    if (res.ok) {
                        if (res.data == null) {
                            resolve(undefined);
                        } else {
                            resolve(res.data);
                        }
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
