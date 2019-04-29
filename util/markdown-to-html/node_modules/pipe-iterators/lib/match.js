var Writable = require('readable-stream').Writable;

require('util').inherits(Match, Writable);

function Match(opts) {
  if (!opts) { opts = {}; }
  opts.objectMode = true;
  Writable.call(this, opts);

  var self = this;
  this._conditions = opts.conditions;
  this._writables = opts.streams;
  this._rest = opts.rest;
  this._ok = this._writables.map(function() { return true; });
  this._counter = 1;

  this._writables.forEach(function(stream, i) {
    stream.on('drain', function() {
      self._ok[i] = true;
    });
    stream.on('error', function(err) { self.emit('error', err); });
  });

  this.once('finish', function() {
    self._writables.forEach(function(stream) {
      stream.end();
    });
  });
}

Match.prototype._write = function(chunk, enc, done) {
  var stream,
      i = -1,
      self = this,
      counter = this.counter++;

  // allow async matchers (arity = 3)
  next(false);

  function next(result) {
    if (result) {
      stream = self._writables[i];
      return last();
    }
    i++;
    if (i < self._conditions.length) {
      if (self._conditions[i].length === 3) {
        self._conditions[i](chunk, counter, next);
      } else {
        next(self._conditions[i](chunk, counter));
      }
    }
  }
  function last() {
    // no match -> call done
    if (!stream) {
      return done();
    }

    function write() {
      if (!self._ok[i]) {
        stream.once('drain', write);
      } else {
        self._ok[i] = stream.write(chunk);
        done();
      }
    }

    write();
  }
};

module.exports = Match;
