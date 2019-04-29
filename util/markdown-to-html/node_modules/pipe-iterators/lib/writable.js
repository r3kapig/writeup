var Writable = require('readable-stream').Writable,
    inherits = require('util').inherits,
    xtend = require('xtend');

function noop(chunk, enc, done) {
  done();
}

function ctor(options, _write) {
  if (typeof options == 'function') {
    _write = options;
    options = {};
  }

  if (typeof _write != 'function') {
    _write = noop;
  }

  function WriteStream(override) {
    this.options = xtend(options, override);
    Writable.call(this, this.options);
  }

  inherits(WriteStream, Writable);
  WriteStream.prototype._write = _write;
  return WriteStream;
}

module.exports = function(options, _write) {
  return new (ctor(options, _write))();
};
module.exports.ctor = ctor;
module.exports.obj = function(_write) {
  return module.exports({ objectMode: true, highWaterMark: 16 }, _write);
};
