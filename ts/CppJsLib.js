"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.CppJsLib = void 0;
/*
 * CppJsLib
 *
 * Licensed under the MIT License
 *
 * Copyright (c) 2021 MarkusJx
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
class CppJsLib {
    /**
     * Create a new CppJsLib instance
     *
     * @param websocketOnly whether to only use websockets for communication
     * @param tls whether to use tls
     * @param host the hostname to connect to
     * @param port the port to connect to
     */
    constructor(websocketOnly = false, tls, host, port) {
        this.loadFunctions = [];
        this.disconnectListeners = [];
        this.connectListeners = [];
        this.exposedFunctions = {};
        this.callbacks = {};
        this.initialized = false;
        this._connected = false;
        this.disconnectTimeoutRunning = false;
        this.disconnectTimeoutSeconds = 10;
        this.enableLogging = false;
        this.webSocket = null;
        this.eventSource = null;
        this.websocketOnly = websocketOnly;
        this.tls = tls == undefined ? (typeof window !== "undefined" ? window.location.protocol === "https:" : false) : tls;
        this.host = host == undefined ? (typeof window !== "undefined" ? window.location.hostname : "") : host;
        this.port = port == undefined ? (typeof window !== "undefined" ? Number(window.location.port) : 0) : port;
    }
    /**
     * Set whether to enable logging
     *
     * @param val set to true to enable logging
     */
    set logging(val) {
        this.enableLogging = val;
    }
    /**
     * Get whether this is connected to the server
     */
    get connected() {
        return this._connected;
    }
    /**
     * Set whether this is connected to the server
     */
    set connected(val) {
        if (this._connected !== val) {
            if (val) {
                this.connectListeners.forEach(fn => fn());
            }
            else {
                this.disconnectListeners.forEach(fn => fn());
            }
        }
        this._connected = val;
    }
    /**
     * Listen for an event. Current events are 'loaded' and 'disconnected'
     *
     * @param event the event name
     * @param listener the listener
     */
    listen(event, listener) {
        if (typeof listener !== 'function') {
            throw new Error("Argument at position 1 is not a function");
        }
        switch (event) {
            case "initizalize":
                if (!this.initialized) {
                    this.loadFunctions.push(listener);
                }
                else {
                    listener();
                }
                break;
            case "disconnect":
                this.disconnectListeners.push(listener);
                if (!this.connected) {
                    listener();
                }
                break;
            case "connect":
                this.connectListeners.push(listener);
                if (this.connected) {
                    listener();
                }
                break;
            default:
                throw new Error(`An event with name ${event} does not exist`);
        }
    }
    /**
     * Unlisten from an event
     *
     * @param event the event name
     * @param fn the listener to remove
     */
    unlisten(event, listener) {
        if (typeof listener !== 'function') {
            throw new Error("Argument at position 1 is not a function");
        }
        switch (event) {
            case "loaded":
                this.loadFunctions.splice(this.loadFunctions.indexOf(listener), 1);
                break;
            case "disconnected":
                this.disconnectListeners.splice(this.disconnectListeners.indexOf(listener), 1);
                break;
            case "connected":
                this.connectListeners.splice(this.connectListeners.indexOf(listener), 1);
                break;
            default:
                throw new Error(`An event with name ${event} does not exist`);
        }
    }
    /**
     * Initialize CppJsLib.
     * Call this before doing anything else.
     * Will call any load listeners once done.
     */
    init() {
        return __awaiter(this, void 0, void 0, function* () {
            if (this.websocketOnly) {
                const wsProtocol = this.tls ? "wss://" : "ws://";
                return new Promise((resolve, reject) => {
                    this.createWebsocket(wsProtocol, this, () => {
                        this.debug("Connected to the websocket server");
                        this.initRequest().then(() => {
                            this.connected = true;
                            resolve();
                        }, reject);
                    });
                });
            }
            else {
                yield this.initRequest();
                const response = yield this.sendHttpRequest("GET", "init_ws", null);
                this.debug("Initializing webSocket with message:", response);
                if (response.ws === true) {
                    const wsProtocol = response.tls ? "wss://" : "ws://";
                    return new Promise(resolve => {
                        this.createWebsocket(wsProtocol, response, () => {
                            this.debug("Connected to the websocket server");
                            this.connected = true;
                            resolve();
                        });
                    });
                }
                else {
                    this.eventSource = new EventSource("cppjslib_events");
                    this.eventSource.onopen = () => {
                        this.debug("Listening for Server Sent Event: cppjslib_events");
                        this.connected = true;
                    };
                    this.eventSource.onerror = (event) => {
                        var _a;
                        if (event.eventPhase == EventSource.CLOSED) {
                            this.debug("SSE connection closed");
                        }
                        else {
                            this.warn("SSE connection error, closing connection");
                        }
                        this.onClose();
                        (_a = this.eventSource) === null || _a === void 0 ? void 0 : _a.close();
                    };
                    this.eventSource.onmessage = this.wsOnMessage.bind(this);
                }
            }
        });
    }
    /**
     * Expose a method to c++
     *
     * @param func the method to expose
     */
    expose(func) {
        this.exposedFunctions[func.name] = func;
    }
    /**
     * Check if the server is reachable
     *
     * @returns true if the server can be reached
     */
    serverReachable() {
        return __awaiter(this, void 0, void 0, function* () {
            const port = location.port.length > 0 ? `:${location.port}` : '';
            try {
                const res = yield fetch(`//${window.location.hostname}${port}/?rand=${Math.random()}`, {
                    method: 'HEAD'
                });
                return res.ok;
            }
            catch (e) {
                this.error("Could not send the request:", e);
                return false;
            }
        });
    }
    /**
     * Send a http request
     *
     * @param method the request method
     * @param path the request path
     * @param body the request body
     * @returns the request result
     */
    sendHttpRequest(method, path, body = null) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const res = yield fetch(path, {
                    method: method,
                    body: body ? JSON.stringify(body) : undefined
                });
                let parsed;
                if (res.headers.get('Content-Type') === "application/json") {
                    parsed = yield res.json();
                }
                else {
                    parsed = yield res.text();
                }
                this.debug("Received request response:", parsed);
                return parsed;
            }
            catch (e) {
                if (!(yield this.serverReachable())) {
                    this.debug("Disconnected");
                    this.onClose();
                }
                throw e;
            }
        });
    }
    /**
     * Send a request
     *
     * @param data the request data
     * @param type the request type. Only required if websocketOnly is false.
     * @returns the request result
     */
    sendRequest(data, type = "POST") {
        return __awaiter(this, void 0, void 0, function* () {
            if (this.websocketOnly) {
                return new Promise((resolve, reject) => {
                    this.callbacks[data.callback] = resolve;
                    const dt = JSON.stringify(data);
                    this.debug("Sending request:", dt);
                    try {
                        this.webSocket.send(dt);
                    }
                    catch (e) {
                        this.debug("Disconnected");
                        this.onClose();
                        delete this.callbacks[data.callback];
                        reject(e);
                    }
                });
            }
            else {
                return this.sendHttpRequest(type, "cppjslib", data);
            }
        });
    }
    /**
     * The close listener
     */
    onClose() {
        if (!this.disconnectTimeoutRunning) {
            this.disconnectTimeoutRunning = true;
            this.connected = false;
            this.debug(`Connection closed. Trying to reconnect in ${this.disconnectTimeoutSeconds} seconds`);
            setTimeout(() => {
                this.disconnectTimeoutRunning = false;
                this.init();
            }, this.disconnectTimeoutSeconds * 1000);
        }
    }
    /**
     * Create a new websocket and connect to the server
     *
     * @param protocol the websocket protocol
     * @param data the data which contains the host and port
     * @param onOpen the open listener
     */
    createWebsocket(protocol, data, onOpen) {
        this.debug(`Connecting to websocket on: ${protocol}${data.host}:${data.port}`);
        this.webSocket = new WebSocket(`${protocol}${data.host}:${data.port}`);
        this.webSocket.onerror = this.wsOnError.bind(this);
        this.webSocket.onclose = this.onClose.bind(this);
        this.webSocket.onmessage = this.wsOnMessage.bind(this);
        this.webSocket.onopen = onOpen;
    }
    /**
     * The init request to be called to get the exported functions
     */
    initRequest() {
        return __awaiter(this, void 0, void 0, function* () {
            // The callback function, which sets the exported functions
            const callback = (response) => {
                this.debug("Initializing with sequence:", response);
                for (let fnName in response) {
                    this.addFunction(fnName, response[fnName]);
                }
                this.loadFunctions.forEach(fn => fn());
                this.initialized = true;
            };
            // When websocket_only is set, send the request via websocket,
            // if not, send the data as a GET request via http
            if (!this.websocketOnly) {
                callback(yield this.sendHttpRequest("GET", "init", null));
            }
            else {
                callback(yield this.sendRequest({
                    header: "init",
                    callback: this.generateCallbackId()
                }));
            }
        });
    }
    /**
     * The websocket on message listener
     *
     * @param event the message event
     */
    wsOnMessage(event) {
        return __awaiter(this, void 0, void 0, function* () {
            this.debug("Received websocket message:", event.data);
            const data = JSON.parse(event.data);
            if (data.header === "callback") {
                if (this.callbacks.hasOwnProperty(data.callback)) {
                    if (data.ok) {
                        this.callbacks[data.callback](data.data);
                    }
                    else {
                        this.callbacks[data.callback](new Error(data.data));
                    }
                    // Delete the callback from the list
                    delete this.callbacks[data.callback];
                }
                else {
                    this.warn("Received data with callback, but this callback does not exist");
                }
            }
            else if (data.header === "call") {
                if (!this.exposedFunctions.hasOwnProperty(data.func)) {
                    this.warn(`C++ tried to call js function ${data.func} which does not exist`);
                    yield this.sendRequest({
                        header: "callback",
                        callback: data.callback,
                        ok: false,
                        data: `The function with name ${data.func} is not exported`
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
                    if (data.data === null) {
                        toSend.data = this.exposedFunctions[data.func]();
                    }
                    else if (data.data.length === 1) {
                        toSend.data = this.exposedFunctions[data.func](data.data[0]);
                    }
                    else {
                        toSend.data = this.exposedFunctions[data.func](...data.data);
                    }
                }
                catch (e) {
                    this.error(`Could not call method ${data.func}:`, e);
                    toSend.ok = false;
                    toSend.data = e.message;
                }
                if (toSend.data === undefined) {
                    toSend.data = null;
                }
                // Let sendRequest handle the sending. Fuck those guys... Wait a second.
                yield this.sendRequest(toSend);
            }
        });
    }
    /**
     * The websocket on error method
     */
    wsOnError() {
        var _a;
        console.warn("Error in websocket. Closing connection.");
        (_a = this.webSocket) === null || _a === void 0 ? void 0 : _a.close();
    }
    /**
     * Add a method to the list of imported methods
     *
     * @param name the name of the method to import
     * @param numArgs the number of arguments of the method
     */
    addFunction(name, numArgs) {
        const self = this;
        this.debug(`Initializing function ${name} with ${numArgs} argument(s)`);
        this[name] = function (...args) {
            if (numArgs !== arguments.length) {
                throw new Error(`Argument count does not match. Expected: ${numArgs} vs. got: ${arguments.length}`);
            }
            return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
                self.debug(`Calling function with args: ${args}`);
                try {
                    const res = yield self.sendRequest({
                        header: "call",
                        func: name,
                        data: args,
                        callback: self.generateCallbackId()
                    });
                    if (res.ok) {
                        resolve(res.data == null ? undefined : res.data);
                    }
                    else {
                        reject(res.data);
                    }
                }
                catch (e) {
                    reject(e);
                }
            }));
        };
    }
    /**
     * Generate a callback id
     *
     * @returns a random callback id
     */
    generateCallbackId() {
        const getId = () => Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
        let rnd = getId();
        while (this.callbacks.hasOwnProperty(rnd)) {
            rnd = getId();
        }
        return rnd;
    }
    /**
     * Log a debug message
     *
     * @param args the arguments to log
     */
    debug(...args) {
        if (this.enableLogging) {
            console.debug(...args);
        }
    }
    /**
     * Log a warning message
     *
     * @param args the arguments to log
     */
    warn(...args) {
        if (this.enableLogging) {
            console.warn(...args);
        }
    }
    /**
     * Log an error message
     *
     * @param args the arguments to log
     */
    error(...args) {
        if (this.enableLogging) {
            console.error(...args);
        }
    }
}
exports.CppJsLib = CppJsLib;
