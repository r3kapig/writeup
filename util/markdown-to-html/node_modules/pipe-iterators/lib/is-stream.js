// Like isstream, but works on Node 0.8.x core streams.
// Also uses duck typing rather than instanceof, which is better for the browser where canonical
// implementations do not exist.

function isStream(obj) {
  return typeof obj === 'object' && (isReadable(obj) || isWritable(obj));
}

function isReadable(obj) {
  return typeof obj === 'object' &&
         typeof obj.pause === 'function' &&
         typeof obj.resume === 'function'; // for internal reasons, every stream has .pipe
}


function isWritable (obj) {
  return typeof obj === 'object' &&
         typeof obj.write === 'function' &&
         typeof obj.end === 'function';
}

function isDuplex (obj) {
  return isReadable(obj) && isWritable(obj);
}

module.exports = isStream
module.exports.isReadable = isReadable;
module.exports.isWritable = isWritable;
module.exports.isDuplex = isDuplex;
