var Readable = require('readable-stream').Readable,
    inherits = require('util').inherits,
    xtend = require('xtend');

function ctor(options, _read) {
  if (_read == null) {
    _read = options;
    options = {};
  }

  if (typeof _read !== 'function') {
    throw new Error('You must implement an _read function');
  }

  function ReadStream(override) {
    this.options = xtend(options, override);
    Readable.call(this, this.options);
  }

  inherits(ReadStream, Readable);
  ReadStream.prototype._read = _read;
  return ReadStream;
}

module.exports = function make(options, _read) {
  return new (ctor(options, _read))();
};
module.exports.ctor = ctor;
module.exports.obj = function(_read) {
  return module.exports({ objectMode: true, highWaterMark: 16 }, _read);
};
