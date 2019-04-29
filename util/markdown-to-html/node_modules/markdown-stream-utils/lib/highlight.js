var hljs = require('highlight.js'),
    through = require('through2');

function hl(code, lang) {
  var result;
  if (typeof lang === 'string' && hljs.getLanguage(lang)) {
    result = hljs.highlight(lang, code, true).value;
  } else {
    result = hljs.highlightAuto(code).value;
  }
  return '<pre class="hljs"><code>' + result + '</code></pre>';
}

module.exports = function(customFn) {
  // code highlighting on lexer output
  return through.obj(function(file, enc, onDone) {
    file.contents.forEach(function(token, index) {
      if(token.type != 'code') {
        return;
      }
      if (customFn) {
        var result = customFn(token.text, token.lang);
        if (!result) {
          result = hl(token.text, token.lang);
        }
      } else {
        result = hl(token.text, token.lang);
      }

      file.contents[index] = { type: 'html', pre: true, text: result };
    });
    this.push(file);
    onDone();
  });
};
