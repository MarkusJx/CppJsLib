const cppJsLib = {
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
        xhttp.send(body);
    },
    'init': function () {
        this.sendRequest("init", (response) => {
            console.log("Initializing with sequence: " + response);
            let obj = JSON.parse(response);
            for (let fnName in obj) {
                if (obj.hasOwnProperty(fnName)) {
                    let args = obj[fnName].toString().split("(");
                    let returnType = args[0].split(" ")[0];
                    args = args[1].replace(")", "").split(", ");
                    this.addFn(returnType, fnName, args);
                }
            }
        }, "", "GET");
    },
    'addFn': function (returnType, name, args) {
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
                    this.sendRequest("callfunc_" + name, resolve, JSON.stringify(obj));
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
        let lastResult = "";
        this.sendRequest("/listenfunc_" + toExpose.name, (response) => {
            lastResult = toExpose(...JSON.parse(response));
            if (typeof lastResult === "undefined") {
                lastResult = "";
            }
            this.expose(toExpose);
        }, lastResult, "GET");
    }
};

cppJsLib.init();