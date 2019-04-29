var through = require('through2'),
    xtend = require('xtend'),
    yaml = require('js-yaml');

function parseMetaHeader(opts) {
  var re = /(-{3,}(\n|\r\n))/g,
      contentsKey = (opts && opts.contentsKey ? opts.contentsKey : 'contents'),
      metadataKey = (opts && opts.metadataKey ? opts.metadataKey : false);

  return through.obj(function (file, enc, onDone) {
    // supports two formats:
    // 1) --- yaml --- ...
    // 2) yaml --- ...
    var startDelim = /^(-{3,}(\n|\r\n))/.exec(file[contentsKey]);

    re.lastIndex = 0;
    if (startDelim) {
      // format 1: begins with a delimiter
      start = re.exec(file[contentsKey]);
      end = re.exec(file[contentsKey]);
    } else {
      // format 2: only ending delimiter
      start = { index: 0, 0: '', 1: '' };
      end = re.exec(file[contentsKey]);
    }

    if (start && end) {
      head = file[contentsKey].toString().slice(start.index + start[0].length, end.index);
      var meta = {};
      try {
        meta = yaml.safeLoad(head, { filename: file.path });
        if (metadataKey) {
          file[metadataKey] = xtend((file[metadataKey] ? file[metadataKey] : {}), meta);
        } else {
          file = xtend(file, meta);
        }
        file[contentsKey] = file[contentsKey].slice(end.index + end[0].length);
      } catch (e) {
        console.log('Could not parse metadata from ' + file.path);
      }
    }
    this.push(file);
    onDone();
  });
}

module.exports = parseMetaHeader;
