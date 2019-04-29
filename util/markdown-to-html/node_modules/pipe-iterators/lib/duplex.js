var Duplex = require('readable-stream').Duplex,
    inherits = require('util').inherits,
    xtend = require('xtend');

function ctor(options, _write, _read) {
  if (typeof options === 'function') {
    _write = options;
    _read = _write;
    options = {};
  }

  if (typeof _write !== 'function') {
    throw new Error('You must implement a _write function');
  }

  if (typeof _read !== 'function') {
    throw new Error('You must implement an _read function');
  }

  function DuplexStream(override) {
    this.options = xtend(options, override);
    Duplex.call(this, this.options);
  }

  inherits(DuplexStream, Duplex);
  DuplexStream.prototype._write = _write;
  DuplexStream.prototype._read = _read;
  return DuplexStream;
}

module.exports = function make(options, _write, _read) {
  return new (ctor(options, _write, _read))();
};
module.exports.ctor = ctor;
module.exports.obj = function(_write, _read) {
  return module.exports({ objectMode: true, highWaterMark: 16 }, _write, _read);
};
