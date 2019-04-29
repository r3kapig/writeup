var path = require('path');

var EXTGLOB_START_CHAR = { '?': true, '*': true, '+': true, '@': true, '!': true };

function parse(glob, opts) {
  var parts = [],
      types = [];
  if (!opts) {
    opts = {};
  }
  scanChunk(glob, function(type, part) {
    if (opts.full) {
      types.push(type);
    }
    parts.push(part);
  });
  return (!opts.full ? parts : { parts: parts, types: types });
};

function scanChunk(glob, onEach) {
  var start, i, numStars = 0;

  function chunk(type, start, i) {
    if (start !== i && i <= glob.length) {
      onEach(type, glob.substring(start, i));
    }
  }

  // todo switch to charAt() for IE7
  for (start = i = 0; i < glob.length; i++) {

    if (EXTGLOB_START_CHAR[glob[i]] && glob[i + 1] === '(') {
      // extglob parser
      chunk('str', start, i);
      start = i;
      i += 2; // skip start char and the open paren
      i = parseUntil(glob, i, '(', ')');
      chunk('ext', start, i);
      start = i;
      continue;
    }

    switch(glob[i]) {
      case '\\':
        if (i === glob.length) {
          throw new Error('No character to escape!');
        }
        i++; // skip next character
        break;
      case '[':
        chunk('str', start, i);
        // set parser
        start = i;
        i = parseUntil(glob, ++i, '[', ']');
        chunk('set', start, i);
        start = i;
        break;
      case '{':
        chunk('str', start, i);
        // brace parser
        start = i;
        i = parseUntil(glob, ++i, '{', '}');
        chunk('brace', start, i);
        start = i;
        break;
      case '?':
        // ? is like a group which excludes '/'
        chunk('str', start, i);
        chunk('?', start, i);
        start = i;
        break;
      case '*':
        // star and starstar parser
        chunk('str', start, i);
        start = i;
        numStars = 1;
        while(glob[++i] === '*') { numStars++; }
        chunk(numStars == 1 ? '*' : '**', start, i);
        start = i;
    }
  }
  chunk('str', start, i);
}

function parseUntil(glob, i, startChar, endChar) {
  var depth = 0;
  do {
    if (glob[i] === '\\') {
      // skip next character as well
      i++;
    } else if (glob[i] === endChar) {
      depth--;
      if (depth === 0 || depth === -1) {
        i++; // current char is part of the pattern
        break;
      }
    } else if (glob[i] === startChar) {
      depth++;
    }
  } while (++i < glob.length);
  return i;
}

module.exports = parse;

module.exports.basename = function(glob) {
  var parsed = parse(glob, { full: true }),
      result = '';

  parsed.parts.some(function(str, i) {
    if (parsed.types[i] !== 'str') {
      return true; // stop iteration
    }
    result += str;
  });

  // always make the base path end with a /
  // this avoids issues with expressions such as `js/t[a-z]` or `js/foo.js`
  var lastSlash = result.lastIndexOf('/', result.length);
  if (lastSlash !== result.length - 1) {
    return result.substring(0, lastSlash + 1);
  }

  return result;
};
