var through = require('through2'),
    cloneLib = require('clone'),
    Readable = require('readable-stream').Readable,
    xtend = require('xtend');

var isStream = require('./lib/is-stream.js'),
    Match = require('./lib/match.js');

// Iteration functions

exports.forEach = function(fn, thisArg) {
  var index = 0;
  thisArg = (typeof thisArg !== 'undefined' ? thisArg : null);
  return through.obj(function(obj, enc, onDone) {
    fn.call(thisArg, obj, index++);
    this.push(obj);
    onDone();
  });
};

exports.map = function(fn, thisArg) {
  var index = 0;
  thisArg = (typeof thisArg !== 'undefined' ? thisArg : null);
  return through.obj(function(obj, enc, onDone) {
    this.push(fn.call(thisArg, obj, index++));
    onDone();
  });
};

exports.reduce = function(fn, initial) {
  var index = 0,
      captureFirst = (arguments.length < 2),
      acc = (!captureFirst ? initial : null);

  return through.obj(function(obj, enc, onDone) {
    if (captureFirst) {
      acc = obj;
      captureFirst = false;
      index++;
    } else {
      acc = fn(acc, obj, index++);
    }
    onDone();
  }, function(onDone) {
    this.push(acc);
    onDone();
  });
};

exports.filter = function(fn, thisArg) {
  var index = 0;
  thisArg = (typeof thisArg !== 'undefined' ? thisArg : null);
  return through.obj(function(obj, enc, onDone) {
    if (fn.call(thisArg, obj, index++)) { this.push(obj); }
    onDone();
  });
};

exports.mapKey = function(first, fn, thisArg) {
  var index = 0;
  if (typeof first === 'string' && typeof fn === 'function') {
    thisArg = (typeof thisArg !== 'undefined' ? thisArg : null);
    return through.obj(function(obj, enc, onDone) {
      obj[first] = fn.call(thisArg, obj[first], obj, index++);
      this.push(obj);
      onDone();
    });
  } else if (typeof first === 'object' && first !== null) {
    thisArg = (typeof fn !== 'undefined' ? fn : null);
    return through.obj(function(obj, enc, onDone) {
      Object.keys(first).forEach(function(key) {
        fn = first[key];
        if (typeof fn === 'function') {
          obj[key] = fn.call(thisArg, obj[key], obj, index++);
        } else {
          obj[key] = fn;
        }
      });
      this.push(obj);
      onDone();
    });
  } else {
    throw new Error('mapKey must be called with: (key, fn) or (hash).');
  }
};

// Input and output

exports.fromArray = function(arr) {
  var eof = false;
  arr = (Array.isArray(arr) ? arr : Array.prototype.slice.call(arguments));

  var stream = exports.readable.obj(function() {
    var item;
    if (arr.length > 0) {
      do {
        item = arr.shift();
      } while(typeof item !== 'undefined' && this.push(item))
    }
    if (arr.length === 0 && !eof) {
      // pushing null signals EOF
      eof = true;
      this.push(null);
    }
  });

  return stream;
};

exports.toArray = function(fn) {
  var endFn = typeof fn === 'function' ? fn : null,
      arr = (Array.isArray(fn) ? fn : []),
      stream = exports.writable.obj(function(chunk, enc, done) {
        arr.push(chunk);
        done();
      });

  if (endFn) {
    stream.once('finish', function() {
      endFn(arr);
      arr = [];
    });
  }
  return stream;
};

exports.fromAsync = function(callable) {
  var called = false;
  var returned = false;
  var eof = false;
  var arr;
  var stream;

  function read() {
    var item;
    if (!called) {
      callable(function(err, results) {
        returned = true;
        if (err) {
          stream.emit('error', err);
          eof = true;
          stream.push(null);
          return;
        }
        arr = Array.isArray(results) ? results : [results];
        read();
      });
      called = true;
      return;
    }
    if (!returned) {
      return;
    }

    if (arr.length > 0) {
      do {
        item = arr.shift();
      } while(typeof item !== 'undefined' && stream.push(item))
    }
    if (arr.length === 0 && !eof) {
      // pushing null signals EOF
      eof = true;
      stream.push(null);
    }
  }

  stream = exports.readable.obj(read);

  return stream;
}

// Constructing streams

exports.thru = exports.through = through;
exports.writable = require('./lib/writable.js');
exports.readable = require('./lib/readable.js');
exports.duplex = require('./lib/duplex.js');

// based on https://github.com/deoxxa/duplexer2/pull/6 (with an additional bugfix)
exports.combine = function(writable, readable) {
  if (!isStream.isWritable(writable)) {
    throw new Error('The first stream must be writable.');
  }
  if (!isStream.isReadable(readable)) {
    throw new Error('The last stream must be readable.');
  }
  if (writable === readable) {
    throw new Error('The two streams must not be === to each other.');
    // ... because it would lead to a bunch of special cases related to duplicate calls
  }

  // convert node 0.8 readable to 0.10 readable stream
  if (typeof readable.read !== 'function') {
    readable = new Readable().wrap(readable);
  }

  var stream = exports.duplex.obj(function(chunk, enc, done) {
        if (!writable.writable) {
          return done(); // if the stream has already ended, stop writing to it
        }
        // Node 0.8.x writable streams do not accept the third parameter, done
        var ok = writable.write(chunk, enc);
        if (ok) {
          done();
        } else {
          writable.once('drain', done);
        }
      }, forwardRead);

  writable.once('finish', function() { stream.end(); });
  stream.once('finish', function() { writable.end(); });

  readable.once('end', function() { stream.push(null); });

  writable.on('error', function(err) { stream.emit('error', err); });
  readable.on('error', function(err) { stream.emit('error', err); });

  function forwardRead() {
    var data, waitingToRead = true;
    while ((data = readable.read()) !== null) {
      waitingToRead = false;
      stream.push(data);
    }
    if (waitingToRead) {
      readable.once('readable', forwardRead);
    }
  }
  return stream;
};

exports.cap = function(duplex) {
  var stream = exports.writable.obj(function(chunk, enc, done) {
    // Node 0.8.x writable streams do not accept the third parameter, done
    var ok = duplex.write(chunk, enc);
    if (ok) {
      done();
    } else {
      duplex.once('drain', done);
    }
  });

  duplex.once('finish', function() { stream.end(); });
  stream.once('finish', function() { duplex.end(); });
  duplex.on('error', function(err) { return stream.emit('error', err); });

  return stream;
};

exports.devnull = function(endFn) {
  var result = exports.writable({ objectMode: true });
  if (endFn) {
    result.once('finish', endFn);
  }
  return result;
};

exports.clone = function() {
  return exports.map(cloneLib);
}

// Control flow

exports.fork = function() {
  var args = (Array.isArray(arguments[0]) ? arguments[0] : Array.prototype.slice.call(arguments)),
      result = through.obj();
  args.forEach(function(target) {
    // to avoid forked streams from interfering with each other, we will have to create a
    // fresh clone for each fork
    result.pipe(exports.clone()).pipe(target);
  });
  return result;
};

function trueFn() { return true; }

function parseMatch(args) {
  var conditions = [],
      streams = [],
      i = 0;

  while (i < args.length) {
    if (typeof args[i] === 'function' && typeof args[i + 1] === 'object') {
      conditions.push(args[i]);
      streams.push(args[i + 1]);
      i += 2;
    } else { break; }
  }
  // the rest-stream is implemented as an appended stream with a condition that's always true
  for (;i < args.length; i++) {
    conditions.push(trueFn);
    streams.push(args[i]);
  }
  return { conditions: conditions, streams: streams };
}

exports.match = function() {
  var args = (Array.isArray(arguments[0]) ? arguments[0] : Array.prototype.slice.call(arguments));
  return new Match(xtend({ objectMode: true }, parseMatch(args)));
};

exports.merge = require('merge-stream');

exports.forkMerge = function() {
  var args = (Array.isArray(arguments[0]) ? arguments[0] : Array.prototype.slice.call(arguments));
  return exports.combine(exports.fork(args), exports.merge(args));
};

exports.matchMerge = function() {
  var args = (Array.isArray(arguments[0]) ? arguments[0] : Array.prototype.slice.call(arguments)),
      parsed = xtend({ objectMode: true }, parseMatch(args));
  return exports.combine(new Match(parsed), exports.merge(parsed.streams));
};

var miniq = require('miniq');

exports.parallel = function(limit, execFn, endFn) {
  if (!execFn) {
    execFn = function(task, enc, done) { task.call(this, done); };
  }
  var queue = miniq(limit),
      cleanup = function(done) {
        queue.removeAllListeners();
        if (endFn) { endFn(done); } else { done(); }
      },
      stream = exports.thru.obj(function(chunk, enc, chunkDone) {
        queue.exec(function(taskDone) {
          execFn.call(stream, chunk, enc, taskDone);
        });
        if (!queue.isFull()) {
          chunkDone(); // ask for more tasks, queue still has space
        } else {
          queue.once('done', function() { chunkDone(); }); // wait until a task completes
        }
      }, function(done) {
        // once "_flush" occurs, wait for the queue to also become empty
        if (queue.isEmpty()) {
          cleanup(done);
        } else {
          queue.once('empty', cleanup.bind(this, done));
        }
      });

  queue.on('done', stream.emit.bind(stream, 'done'));
  queue.on('error', stream.emit.bind(stream, 'error'));
  queue.on('empty', stream.emit.bind(stream, 'empty'));

  return stream;
};

// Constructing pipelines from individual elements

exports.pipe = function() {
  var args = (Array.isArray(arguments[0]) ? arguments[0] : Array.prototype.slice.call(arguments));
  if (!isStream.isReadable(args[0])) {
    throw new Error('pipe(): First stream must be readable.');
  }

  if (!isStream.isWritable(args[0])) {
    throw new Error('pipe(): Last stream must be writable.');
  }

  args.slice(1, -1).map(function(stream) {
    if (!isStream.isDuplex(stream)) {
      throw new Error('pipe(): Streams in the pipeline must be duplex.');
    }
  });

  args.reduce(function(prev, curr) { return prev.pipe(curr); });
  return args;
}

exports.head = function() {
  var args = (Array.isArray(arguments[0]) ? arguments[0] : Array.prototype.slice.call(arguments));
  return exports.pipe(args)[0];
};

exports.tail = function() {
  var args = (Array.isArray(arguments[0]) ? arguments[0] : Array.prototype.slice.call(arguments));
  return exports.pipe(args).pop();
};

exports.pipeline = function() {
  var streams = exports.pipe((Array.isArray(arguments[0]) ? arguments[0] : Array.prototype.slice.call(arguments)));
  if (streams.length === 1) {
    return streams[0];
  }

  var last = streams[streams.length - 1],
      isDuplex = isStream.isDuplex(last),
      head = isDuplex ? exports.combine(streams[0], last) : exports.cap(streams[0]);

  // listen to errors in the middle streams (combine already listens to the first and last)
  streams.slice(1, (isDuplex ? -1 : streams.length)).forEach(function(stream) {
    stream.on('error', function(err) { head.emit('error', err); });
  });

  return head;
};

// isStream

exports.isStream = isStream;
exports.isReadable = isStream.isReadable;
exports.isWritable = isStream.isWritable;
exports.isDuplex = isStream.isDuplex;

