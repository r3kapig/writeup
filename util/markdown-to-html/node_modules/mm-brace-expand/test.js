var assert = require('assert'),
    expand = require('./index.js');

exports['tests'] = {

  'a{b,c{d,e},{f,g}h}x{y,z}': function() {
    assert.deepEqual(
      expand('a{b,c{d,e},{f,g}h}x{y,z}'),
      [ 'abxy', 'abxz',
        'acdxy', 'acdxz',
        'acexy', 'acexz',
        'afhxy', 'afhxz',
        'aghxy', 'aghxz']
      );
  },

  'a{1..5}b': function() {
    assert.deepEqual(
      expand('a{1..5}b'),
        [ 'a1b', 'a2b', 'a3b', 'a4b', 'a5b' ]
    );
  },

  'a{b}c': function() {
    assert.deepEqual(expand('a{b}c'), [ 'a{b}c' ]);
  },

  'a{00..05}b': function () {
    assert.deepEqual(
      expand('a{00..05}b'),
      [ 'a00b', 'a01b', 'a02b', 'a03b', 'a04b', 'a05b' ]
    );
  },

  // via https://github.com/juliangruber/brace-expansion

  'numeric sequences': function() {
    assert.deepEqual(expand('a{1..2}b{2..3}c'),
      [ 'a1b2c', 'a1b3c', 'a2b2c', 'a2b3c' ]);
    assert.deepEqual(expand('{1..2}{2..3}'),
      [ '12', '13', '22', '23']);
  },

  /*
  'numeric sequences with step count': function() {
    assert.deepEqual(expand('{0..8..2}'), [
      '0', '2', '4', '6', '8'
    ]);
    assert.deepEqual(expand('{1..8..2}'), [
      '1', '3', '5', '7', '8'
    ]);
  },

  'numeric sequence with negative x / y': function() {
    assert.deepEqual(expand('{3..-2}'), [
      '3', '2', '1', '0', '-1', '-2'
    ]);
  },

  'alphabetic sequences': function() {
    assert.deepEqual(expand('1{a..b}2{b..c}3'), [
      '1a2b3', '1a2c3', '1b2b3', '1b2c3'
    ]);
    assert.deepEqual(expand('{a..b}{b..c}'), [
      'ab', 'ac', 'bb', 'bc'
    ]);
  },

  'alphabetic sequences with step count': function() {
    assert.deepEqual(expand('{a..k..2}'), [
      'a', 'c', 'e', 'g', 'i', 'k'
    ]);
    assert.deepEqual(expand('{b..k..2}'), [
      'b', 'd', 'f', 'h', 'j', 'k'
    ]);
  }
  */
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
