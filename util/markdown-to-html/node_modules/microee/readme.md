# microEE

A client and server side library for routing events.

[![Build Status](https://secure.travis-ci.org/mixu/microee.png?branch=master)](https://travis-ci.org/mixu/microee)

I was disgusted by the size of [MiniEE](https://github.com/mixu/miniee) (122 sloc, 4.4kb), so I decided a rewrite was in order.

MicroEE is a more satisfying (~50 sloc, ~1200 characters), and passes the same tests as MiniEE (excluding the RegExp support, but including many real-world tests, such as removing a once() callback, and checking for the correct order of once callback removal).

# Installing:

    npm install microee

# In-browser version

Use the version in `./dist/`. It exports a single global, `microee`.

To run the in-browser tests, open `./test/index.html` in the browser after cloning this repo and doing npm install (to get Mocha).

# Usage example: `microee.mixin`

    var MicroEE = require('microee');
    function MyClass() {
      // ...
    }
    MicroEE.mixin(MyClass);
    MyClass.prototype.foo = function() {
      // ...
    };

    var obj = new MyClass();
    // set string callback
    obj.on('event', function(arg1, arg2) { console.log(arg1, arg2); });
    obj.emit('event', 'aaa', 'bbb'); // trigger callback

# API

The API is based on [Node's EventEmitter](http://nodejs.org/api/events.html).

There are two additional niceties: `emitter.when(event, listener)` and `.mixin()`.

Support for `emitter.listeners(event)` was added in `v0.0.6`.

## emitter.on(event, listener)

Adds a listener to the end of the listeners array for the specified event.

```
server.on('connection', function (stream) {
  console.log('someone connected!');
});
```

Returns emitter, so calls can be chained.

## emitter.once(event, listener)

Adds a one time listener for the event. This listener is invoked only the next time the event is fired, after which it is removed.

Returns emitter, so calls can be chained.

## emitter.when(event, listener)

Addition to the regular API. If `listener` returns true, the listener is removed. Useful for waiting for a particular set of parameters on a recurring event e.g. in tests.

Returns emitter, so calls can be chained.

## microee.mixin(object)

Addition to the regular API. Extends `object.prototype` with all the microee methods, allowing other classes to act like event emitters.

## emitter.emit(event, [arg1], [arg2], [...])

Execute all listeners on `event`, with the supplied arguments.

Returns emitter, so calls can be chained.

## emitter.removeListener(event, listener)

Remove a listener from the listener array for the specified event.

## emitter.removeAllListeners([event])

Removes all listeners, or those of the specified event.

## emitter.listeners(event)

Returns an array of listeners for the specified event.
