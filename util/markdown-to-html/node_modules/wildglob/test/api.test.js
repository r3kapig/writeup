var fs = require('fs'),
    assert = require('assert'),
    Fixture = require('file-fixture'),
    glob = require('../index.js');

exports['API tests'] = {

  before: function() {
    this.fixture = new Fixture();

    this.fixDir = this.fixture.dir({
      'vendor/js/foo.js': 'test',
      'vendor/js/bar.js': 'test',
      'vendor/js/baz.js': 'test'
    }, {});
  },

  'calls with no opts cwd': {

    before: function() {
      this.oldCwd = process.cwd();
      process.chdir(this.fixDir);
    },

    after: function() {
      process.chdir(this.oldCwd);
    },

    'glob.async works': function(done) {
      glob('**/ba*.js', function(err, files) {
        assert.ok(!err);
        assert.deepEqual(files.sort(), ['vendor/js/bar.js', 'vendor/js/baz.js']);
        done();
      });
    },

    'glob.sync works': function() {
      var files = glob.sync('**/ba*.js');
      assert.deepEqual(files.sort(), ['vendor/js/bar.js', 'vendor/js/baz.js']);
    },

    'glob.stream works': function(done) {
      var files = [];
      glob.stream('**/ba*.js')
          .on('error', function(err) { throw err; })
          .on('data', function(filepath) { files.push(filepath); })
          .once('end', function() {
            assert.deepEqual(files.sort(), ['vendor/js/bar.js', 'vendor/js/baz.js']);
            done();
          });
    }
  },

  'can change the glob matcher': function() {
    var calls = [];
    var files = glob.sync('*', {
      cwd: this.fixDir,
      match: function(filepath, pattern) {
        assert.equal(pattern, '*');
        calls.push(filepath);
        return true;
      }
    });

    var all = ['vendor', 'vendor/js', 'vendor/js/bar.js', 'vendor/js/baz.js', 'vendor/js/foo.js'];

    assert.deepEqual(files.sort(), all);
    assert.deepEqual(calls.sort(), all);
  },

  'can set abspath = true and receive absolute paths': function() {
    var self = this,
        files = glob.sync('./**/*.*', { abspath: true, cwd: this.fixDir });

    assert.deepEqual(files.sort(),
      ['vendor/js/bar.js', 'vendor/js/baz.js', 'vendor/js/foo.js'].map(function(p) {
        return self.fixDir + '/' + p;
      })
    );
  }

//  'can add negated patterns, values matching negated patterns are excluded': function() {
//    var files = glob.sync(['**/*.js', '!**/*z.js']);
//    assert.deepEqual(files, ['vendor/js/bar.js'] );
//  },
//
//  'can change the root mount point': function() {
//    var files = glob.sync('/foo/bar', { root: });
//
//  },
//  'can remove duplicates': function() {
//
//  },
//  'can remove duplicates taking abspath into account': function() {
//
//  },

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
