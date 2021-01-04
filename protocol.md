# CppJsLib protocol definition

Each message is sent via either a http request or using the websocket protocol. The messages are encoded in the JSON
format.

## Init message

The init message is sent via http using a ``GET`` request with the path ``init``. If the server is started without the
http(s) server, the request is sent via websocket in the format

```json
{
  "header": "init",
  "callback": "[RANDOM-CALLBACK-ID]"
}
```

The server responds with a json-encoded message, containing the exported functions and their expected number of
arguments. Example for a http response:

```json
{
  "some_func": 2,
  "another_func": 4
}
```

When ``websocket_only`` is set, this object is sent via a callback response. So it looks like this:

```json
{
  "header": "callback",
  "callback": "YZNXNsNBnMSXO2msjegDqqGw6M8wNjKqLxnjEbBu",
  "data": {
    "some_func": 2,
    "another_func": 4
  }
}
```

## Callbacks

A callback (a response to a previous request or function call) looks like this:

```json
{
  "header": "callback",
  "callback": "[CALLBACK_ID_TO_RESPOND]",
  "data": "[SOME_DATA]"
}
```

Arguments:

* ``header``: must be ``callback``
* ``callback``: the random callback id
* ``data``: the response data

## Function calls

### Function call

A function call has the form:

```json
{
  "header": "call",
  "func": "some_func",
  "data": "[0,\"/watch?v=dQw4w9WgXcQ\"]",
  "callback": "YZNXNsNBnMSXO2msjegDqqGw6M8wNjKqLxnjEbBu"
}
```

Arguments:

* ``header``: must be ``call``
* ``func``: the name of the function to call
* ``data``: the function arguments as an array
* ``callback``: the callback id (randomly generated)

### Function callback

Function return values or exceptions are transferred using callbacks:

```json
{
  "header": "callback",
  "data": "0",
  "ok": true,
  "callback": "YZNXNsNBnMSXO2msjegDqqGw6M8wNjKqLxnjEbBu"
}
```

Arguments:

* ``header``: must be ``callback``
* ``data``: the return value or an error message
* ``ok``: is set to true, when the function call was successful (no exception thrown)
* ``callback``: the callback id this is a response to