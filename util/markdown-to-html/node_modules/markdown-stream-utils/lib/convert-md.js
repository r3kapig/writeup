var through = require('through2'),
    marked = require('marked'),
    xtend = require('xtend');

var defaults = marked.defaults;

function convertMd(opts) {
  var parser = new marked.Parser(xtend(defaults, opts));

  // override Parser.prototype.tok so that we can get direct access to the underlying token
  // to avoid generating the same id multiple times in multiple places

  parser.tok = function() {
    if (this.token.type === 'heading') {
      return this.renderer.heading(
              this.inline.output(this.token.text),
              this.token.depth,
              this.token.text,
              this.token);
    }

    return marked.Parser.prototype.tok.apply(this, Array.prototype.slice.call(arguments));
  };

  return through.obj(function(file, enc, onDone) {
    file.contents = parser.parse(file.contents);
    // push to next transform
    this.push(file);
    onDone();
  });
}

module.exports = convertMd;
