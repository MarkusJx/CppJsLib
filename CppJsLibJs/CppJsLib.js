const cppJsLib = {
    /**
     * @type [function]
     */
    'loadFunctions': [],
    'initialized': false,
    'exposedFunctions': [],
    'connected': false,
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
    'sendRequest': function (request, callback = false, body = "", type = "POST") {
        let xhttp = new XMLHttpRequest();
        xhttp.open(type, request, true);
        if (callback) {
            xhttp.onreadystatechange = function () {
                if (this.readyState === 4 && this.status === 200) {
                    callback(xhttp.responseText);
                }
            };
        }
        try {
            xhttp.send(body);
        } catch (error) {
            this.connected = false;
        }
    },
    'init': function () {
        this.sendRequest("init", (response) => {
            console.log("Initializing with sequence: " + response);
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
            if (obj["ws"] === "true") {
                let wsProtocol;
                if(obj["tls"] === "true") {
                    wsProtocol = "wss://";
                } else {
                    wsProtocol = "ws://";
                }

                console.log("Connecting to websocket on: " + wsProtocol + obj["host"] + ":" + obj["port"]);
                this.webSocket = new WebSocket(wsProtocol + obj["host"] + ":" + obj["port"]);
                this.connected = true;
                this.webSocket.onclose = () => {
                    this.connected = false;
                    console.log("WebSocket connection closed");
                };
                this.webSocket.onmessage = (event) => {
                    let data = JSON.parse(event.data);
                    let key = Object.keys(data)[0];
                    if (data[key].length === 1) {
                        if (data[key][0] === "") {
                            this.exposedFunctions[key]();
                        } else {
                            this.exposedFunctions[key](JSON.parse(data[key]));
                        }
                    } else {
                        this.exposedFunctions[key]( ... JSON.parse(data[key]));
                    }
                }
            }
        }, "", "GET");
    },
    'addFn': function (returnType, name, args) {
        console.log("Initializing function " + name + " with " + args.length + " argument(s) " + args);
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
                            res = (res === "1");
                        }
                        if (res.startsWith("\"")) {
                            resolve(JSON.parse(res));
                        } else {
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

cppJsLib.init();