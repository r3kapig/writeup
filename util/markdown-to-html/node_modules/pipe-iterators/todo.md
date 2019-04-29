## Input helpers

- .fromAsync(callable): callable is a function(onDone) which performs an async task and returns either: 
  1. a single item (emitted)
  2. an array of items (emitted individually)
  
- .log(depth): shortcut for `pi.forEach(function(item) { console.log(util.inspect(item, null, depth || 20)); })`

- .read(): duplex, reads objs from FS
- .write(): writable, writes to FS
- .httpGet(): duplex, reads objs from HTTP
- .httpsGet(): duplex, reads objs from HTTPS

# Auto error wrapping

- to make debugging easier, some kind of auto-try-catch mode
