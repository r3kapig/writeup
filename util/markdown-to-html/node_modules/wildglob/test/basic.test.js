var fs = require('fs'),
    path = require('path'),
    assert = require('assert'),
    Fixture = require('file-fixture'),
    glob = require('../index.js');

exports['basic tests'] = {

  before: function() {
    this.fixture = new Fixture();

    this.basicFixtureDir = this.fixture.dir({
      'foo/aa.js': 'test',
      'foo/bar/aa.js': 'test',
      'foo/bar/aa.txt': 'test'
    }, {});

    this.relativeFixtureDir = this.fixture.dir({
      'a/.abcdef/x/y/z/a': 'i like tests',
      'a/abcdef/g/h': 'i like tests',
      'a/abcfed/g/h': 'i like tests',
      'a/b/c/d': 'i like tests',
      'a/bc/e/f': 'i like tests',
      'a/c/d/c/b': 'i like tests',
      'a/cb/e/f': 'i like tests'
    }, {});
/*
    this.absFixtureDir = this.fixture.dirname();
    [ 'foo', 'bar', 'baz', 'asdf', 'quux', 'qwer', 'rewq'].forEach(function (w) {
      fs.mkdirSync(self.absFixtureDir + '/' + w);
    });
*/
  },

  'passing in a empty value': {

    'sync': function() {
      var result = glob.sync();
      assert.deepEqual(result, []);
    },

    'async': function(done) {
      var result = glob(undefined, function(err, result) {
        assert.deepEqual(result, []);
        done();
      });
    },

    'stream': function(done) {
      var result = [];
      glob.stream()
          .on('error', function(err) { throw err; })
          .on('data', function(filepath) { result.push(filepath); })
          .once('end', function() {
            assert.deepEqual(result, []);
            done();
          });
    }
  },

  'basic sync': {
    'foo/**/*.js works': function() {
      var result = glob.sync('foo/**/*.js', { cwd: this.basicFixtureDir }).sort();
      assert.deepEqual(result, ['foo/aa.js', 'foo/bar/aa.js']);
    },

    './foo/**/*.js works': function() {
      var result = glob.sync('./foo/**/*.js', { cwd: this.basicFixtureDir }).sort();
//      console.log(result);
      assert.deepEqual(result, ['./foo/aa.js', './foo/bar/aa.js']);
    },

    '__dirname + /foo/**/*.js works': function() {
      var self = this,
          result = glob.sync(this.basicFixtureDir + '/foo/**/*.js').sort();
//      console.log(result);
      assert.deepEqual(result, ['foo/aa.js', 'foo/bar/aa.js'].map(function(str) {
        return self.basicFixtureDir + '/' + str;
      }));
    }
  },

  'cwd-test.js - changing cwd and searching for **/d': {

    'before': function() {
      this.origCwd = process.cwd();
      process.chdir(this.relativeFixtureDir);
    },

    'after': function() {
      process.chdir(this.origCwd);
    },

    'cwd-test .': function() {
      var result = glob.sync('**/d').sort();
//      console.log(result);
      assert.deepEqual(result, ['a/b/c/d', 'a/c/d']);
    },

    'cwd-test a': function() {
      var result = glob.sync('**/d', { cwd: path.resolve('a') }).sort();
//      console.log(result);
      assert.deepEqual(result, ['b/c/d', 'c/d']);
    },

    'cwd-test a/b': function() {
      var result = glob.sync('**/d', { cwd: path.resolve('a/b') });
//      console.log(result);
      assert.deepEqual(result, ['c/d']);
    },

    'cwd-test a/b/': function() {
      var result = glob.sync('**/d', { cwd: path.resolve('a/b/') });
//      console.log(result);
      assert.deepEqual(result, ['c/d']);
    },

    'cwd-test process.cwd': function() {
      var result = glob.sync('**/d', { cwd: process.cwd() }).sort();
//      console.log(result);
      assert.deepEqual(result, ['a/b/c/d', 'a/c/d']);
    }
  },

  'empty-set.js - Patterns that cannot match anything': {
    'empty-set "# comment"': function() {
      var result = glob.sync('# comment').sort();
//      console.log(result);
      // no error thrown
      assert.deepEqual(result, []);
    },

    'empty-set " "': function() {
      var result = glob.sync(' ').sort();
//      console.log(result);
      // no error thrown
      assert.deepEqual(result, []);
    },

    'empty-set "\\n"': function() {
      var result = glob.sync('\n').sort();
//      console.log(result);
      // no error thrown
      assert.deepEqual(result, []);
    },

    'empty-set "just doesnt happen to match anything so this is a control"': function() {
      var result = glob.sync('just doesnt happen to match anything so this is a control').sort();
//      console.log(result);
      // no error thrown
      assert.deepEqual(result, []);
    }
  },

  'error-callback.js - Ensure that fs errors do not cause duplicate errors': {

    before: function() {
      this.oldReaddir = fs.readdir;
      this.oldReaddirSync = fs.readdirSync;

      fs.readdir = function(path, cb) {
        process.nextTick(function() {
          cb(new Error('mock fs.readdir error'));
        });
      };

      fs.readdirSync = function(path) {
        throw new Error('mock fs.readdirSync error');
      };
    },

    'error callback - sync': function() {
      var err = false;
      try {
        glob.sync('*', { fs: fs });
      } catch (e) {
        // expecting an error
        err = e;
      }
      assert.ok(err, 'expecting error');
    },

    'error callback - async': function(done) {
      glob('*', { fs: fs }, function(err) {
        assert.ok(err);
        done();
      });
    },

    after: function() {
      fs.readdir = this.oldReaddir;
      fs.readdirSync = this.oldReaddirSync;
    }
  }
};

// if this module is the script being run, then run the tests:
if (module == require.main) {
  var mocha = require('child_process').spawn('mocha', [
    '--colors', '--bail', '--ui', 'exports', '--reporter', 'spec', __filename
  ]);
  mocha.stderr.on('data', function(data) {
    if (/^execvp\(\)/.test(data)) {
     console.log('Failed to start child process. You need mocha: `npm install -g mocha`');
    }
  });
  mocha.stdout.pipe(process.stdout);
  mocha.stderr.pipe(process.stderr);
}
