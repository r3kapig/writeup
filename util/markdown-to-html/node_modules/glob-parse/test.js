var assert = require('assert'),
    parse = require('./index.js');

exports['tests'] = {

  'parse': {
    'should get a base name': function() {
      var result = parse('js/*.js' , { full: true });
      assert.deepEqual(result.parts, ['js/', '*', '.js']);
      assert.deepEqual(result.types, [ 'str', '*', 'str' ]);
    },

    'should get a base name from a nested glob': function() {
      var result = parse('js/**/test/*.js', { full: true });
      assert.deepEqual(result.parts, [ 'js/', '**', '/test/', '*', '.js' ]);
      assert.deepEqual(result.types, [ 'str', '**', 'str', '*', 'str' ]);
    },

    'should get a base name from a flat file': function() {
      var result = parse('js/test/wow.js', { full: true });
      assert.deepEqual(result.parts, ['js/test/wow.js']);
      assert.deepEqual(result.types, [ 'str' ]);
    },

    'should get a base name from character class pattern': function() {
      var result = parse('js/t[a-z]st/*.js', { full: true });
      assert.deepEqual(result.parts, ['js/t', '[a-z]', 'st/', '*', '.js' ]);
      assert.deepEqual(result.types, [ 'str', 'set', 'str', '*', 'str' ]);
    },

    'should get a base name from brace , expansion': function() {
      var result = parse('js/{src,test}/*.js', { full: true });
      assert.deepEqual(result.parts, ['js/', '{src,test}', '/', '*', '.js']);
      assert.deepEqual(result.types, [ 'str', 'brace', 'str', '*', 'str' ]);
    },

    'should get a base name from brace .. expansion': function() {
      var result = parse('js/test{0..9}/*.js', { full: true });
      assert.deepEqual(result.parts, [ 'js/test', '{0..9}', '/', '*', '.js']);
      assert.deepEqual(result.types, [ 'str', 'brace', 'str', '*', 'str' ]);
    },

    'should get a base name from extglob': function() {
      var result = parse('js/t+(wo|est)/*.js', { full: true });
      assert.deepEqual(result.parts, [ 'js/t', '+(wo|est)', '/', '*', '.js']);
      assert.deepEqual(result.types, [ 'str', 'ext', 'str', '*', 'str' ]);
    },

    'should get a base name from a complex brace glob #1': function() {
      var result = parse('lib/{components,pages}/**/{test,another}/*.txt', { full: true });
      assert.deepEqual(result.parts,
        ['lib/', '{components,pages}', '/', '**', '/', '{test,another}', '/', '*', '.txt']);
      assert.deepEqual(result.types,
        [ 'str', 'brace', 'str', '**', 'str', 'brace', 'str', '*', 'str' ]);
    },

    'should get a base name from a complex brace glob #2': function() {
      var result = parse('js/test/**/{images,components}/*.js', { full: true });
      assert.deepEqual(result.parts,
        ['js/test/', '**', '/', '{images,components}', '/', '*', '.js']);
      assert.deepEqual(result.types,
        [ 'str', '**', 'str', 'brace', 'str', '*', 'str' ]);
    },

    'should get a base name from a complex brace glob #3': function() {
      var result = parse('ooga/{booga,sooga}/**/dooga/{eooga,fooga}', { full: true });
      assert.deepEqual(result.parts,
        ['ooga/', '{booga,sooga}', '/', '**', '/dooga/', '{eooga,fooga}']);
      assert.deepEqual(result.types,
        [ 'str', 'brace', 'str', '**', 'str', 'brace' ]);
    },

    'test/a/*/+(c|g)/./d': function() {
      var result = parse('test/a/*/+(c|g)/./d', { full: true });
      assert.deepEqual(result.parts, ['test/a/', '*', '/', '+(c|g)', '/./d']);
      assert.deepEqual(result.types, [ 'str', '*', 'str', 'ext', 'str' ]);
    },

    'test/a/**/[cg]/../[cg]': function() {
      var result = parse('test/a/**/[cg]/../[cg]', { full: true });
      assert.deepEqual(result.parts, [ 'test/a/', '**', '/', '[cg]', '/../', '[cg]' ]);
      assert.deepEqual(result.types, [ 'str', '**', 'str', 'set', 'str', 'set' ]);
    },

    'test/a/{b,c,d,e,f}/**/g': function() {
      var result = parse('test/a/{b,c,d,e,f}/**/g', { full: true });
      assert.deepEqual(result.parts, [ 'test/a/', '{b,c,d,e,f}', '/', '**', '/g' ]);
      assert.deepEqual(result.types, [ 'str', 'brace', 'str', '**', 'str' ]);
    },

    'test/a/b/**': function() {
      var result = parse('test/a/b/**', { full: true });
      assert.deepEqual(result.parts, [ 'test/a/b/', '**' ]);
      assert.deepEqual(result.types, [ 'str', '**' ]);
    },

    'test/**/g': function() {
      var result = parse('test/**/g', { full: true });
      assert.deepEqual(result.parts, [ 'test/', '**', '/g' ]);
      assert.deepEqual(result.types, [ 'str', '**', 'str' ]);
    },

    'test/a/abc{fed,def}/g/h': function() {
      var result = parse('test/a/abc{fed,def}/g/h', { full: true });
      assert.deepEqual(result.parts, [ 'test/a/abc', '{fed,def}', '/g/h' ]);
      assert.deepEqual(result.types, [ 'str', 'brace', 'str' ]);
    },

    'test/a/abc{fed/g,def}/**/': function() {
      var result = parse('test/a/abc{fed/g,def}/**/', { full: true });
      assert.deepEqual(result.parts, [ 'test/a/abc', '{fed/g,def}', '/', '**', '/' ]);
      assert.deepEqual(result.types, [ 'str', 'brace', 'str', '**', 'str' ]);
    },

    'test/a/abc{fed/g,def}/**///**/': function() {
      var result = parse('test/a/abc{fed/g,def}/**///**/', { full: true });
      assert.deepEqual(result.parts, [ 'test/a/abc', '{fed/g,def}', '/', '**', '///', '**', '/' ]);
      assert.deepEqual(result.types, [ 'str', 'brace', 'str', '**', 'str', '**', 'str' ]);
    },

    'test/**/a/**/': function() {
      var result = parse('test/**/a/**/', { full: true });
      assert.deepEqual(result.parts, [ 'test/', '**', '/a/', '**', '/' ]);
      assert.deepEqual(result.types, [ 'str', '**', 'str', '**', 'str' ]);
    },

    'test/+(a|b|c)/a{/,bc*}/**': function() {
      var result = parse('test/+(a|b|c)/a{/,bc*}/**', { full: true });
      assert.deepEqual(result.parts, [ 'test/', '+(a|b|c)', '/a', '{/,bc*}', '/', '**' ]);
      assert.deepEqual(result.types, [ 'str', 'ext', 'str', 'brace', 'str', '**' ]);
    },

    'test/*/*/*/f': function() {
      var result = parse('test/*/*/*/f', { full: true });
      assert.deepEqual(result.parts, [ 'test/', '*', '/', '*', '/', '*', '/f' ]);
      assert.deepEqual(result.types, [ 'str', '*', 'str', '*', 'str', '*', 'str' ]);
    },

    'test/**/f': function() {
      var result = parse('test/**/f', { full: true });
      assert.deepEqual(result.parts, [ 'test/', '**', '/f' ]);
      assert.deepEqual(result.types, [ 'str', '**', 'str' ]);
    },

    'test/a/symlink/a/b/c/a/b/c/a/b/c//a/b/c////a/b/c/**/b/c/**': function() {
      var result = parse('test/a/symlink/a/b/c/a/b/c/a/b/c//a/b/c////a/b/c/**/b/c/**', { full: true });
      assert.deepEqual(result.parts,
        [ 'test/a/symlink/a/b/c/a/b/c/a/b/c//a/b/c////a/b/c/', '**', '/b/c/', '**' ]);
      assert.deepEqual(result.types,
        [ 'str', '**', 'str', '**' ]);
    },

    '{./*/*,/tmp/glob-test/*}': function() {
      var result = parse('{./*/*,/tmp/glob-test/*}', { full: true });
      assert.deepEqual(result.parts, [ '{./*/*,/tmp/glob-test/*}' ]);
      assert.deepEqual(result.types, [ 'brace' ]);
    },

    '{/tmp/glob-test/*,*}': function() {
      var result = parse('{/tmp/glob-test/*,*}', { full: true });
      assert.deepEqual(result.parts, [ '{/tmp/glob-test/*,*}' ]);
      assert.deepEqual(result.types, [ 'brace' ]);
    },

    'test/a/!(symlink)/**': function() {
      var result = parse('test/a/!(symlink)/**', { full: true });
      assert.deepEqual(result.parts, [ 'test/a/', '!(symlink)', '/', '**' ]);
      assert.deepEqual(result.types, [ 'str', 'ext', 'str', '**' ]);
    }

  },

  'basename': {
    'should get a base name': function() {
      assert.equal(parse.basename('js/*.js'), 'js/');
    },

    'should get a base name from a nested glob': function() {
      assert.equal(parse.basename('js/**/test/*.js'), 'js/');
    },

    'should get a base name from a flat file': function() {
      assert.equal(parse.basename('js/test/wow.js'), 'js/test/');
    },

    'should get a base name from character class pattern': function() {
      assert.equal(parse.basename('js/t[a-z]st/*.js'), 'js/');
    },

    'should get a base name from brace , expansion': function() {
      assert.equal(parse.basename('js/{src,test}/*.js'), 'js/');
    },

    'should get a base name from brace .. expansion': function() {
      assert.equal(parse.basename('js/test{0..9}/*.js'), 'js/');
    },

    'should get a base name from extglob': function() {
      assert.equal(parse.basename('js/t+(wo|est)/*.js'), 'js/');
    },

    'should get a base name from a complex brace glob #1': function() {
      assert.equal(parse.basename('lib/{components,pages}/**/{test,another}/*.txt'), 'lib/');
    },

    'should get a base name from a complex brace glob #2': function() {
      assert.equal(parse.basename('js/test/**/{images,components}/*.js'), 'js/test/');
    },

    'should get a base name from a complex brace glob #3': function() {
      assert.equal(parse.basename('ooga/{booga,sooga}/**/dooga/{eooga,fooga}'), 'ooga/');
    }

//     '{./*/*,/tmp/glob-test/*}': function() {
//       var result = parse.basename('{./*/*,/tmp/glob-test/*}', { full: true });
//       assert.deepEqual(result.parts, [ '{./*/*,/tmp/glob-test/*}' ]);
//     },
//
//     '{/tmp/glob-test/*,*}': function() {
//       var result = parse.basename('{/tmp/glob-test/*,*}');
//       assert.deepEqual(result, [ '/tmp/glob-test/' ]);
//     },

  }
};


// if this module is the script being run, then run the tests:
if (module == require.main) {
  var mocha = require('child_process').spawn('mocha',
    ['--colors', '--ui', 'exports', '--reporter', 'spec', __filename]);
  mocha.on('error', function() {
     console.log('Failed to start child process. You need mocha: `npm install -g mocha`');
  });
  mocha.stderr.on('data', function(data) {
    if (/^execvp\(\)/.test(data)) {
     console.log('Failed to start child process. You need mocha: `npm install -g mocha`');
    }
  });
  mocha.stdout.pipe(process.stdout);
  mocha.stderr.pipe(process.stderr);
}
