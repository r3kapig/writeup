var fs = require('fs'),
    assert = require('assert'),
    Fixture = require('file-fixture'),
    glob = require('../index.js'),
    expand = require('mm-brace-expand'),
    childProcess = require('child_process'),
    rimraf = require('rimraf');

function runBash(cmd, opts, onDone) {
  childProcess.execFile('/bin/bash', ['-c', cmd], opts, function(err, stdout, stderr) {
    console.log(stdout);
    console.log(stderr);
    if (err) {
      throw err;
    }
    onDone();
  });
}

exports.tests = {

  before: function(done) {
    var self = this;
    this.timeout(600 * 1000);
    this.fixture = new Fixture();

    // 10k dirs of 10 files each = 100k files
    var filenames = expand('{0..9}/{0..9}/{0..9}/{0..9}/{0..9}.txt'),
        spec = {};

    filenames.forEach(function(name) {
      spec[name] = 'test';
    });

    console.log('Setting up ' + filenames.length + ' files');
    this.target = this.fixture.dir(spec, {});
    console.log('Created folders in', this.target);
    console.log('Installing npm modules');
    runBash('npm install glob wildmatch globy', { cwd: this.target }, function() {
      console.log('Installed glob wildmatch globy.');
      runBash('npm link wildglob', { cwd: self.target }, function() {
        console.log('npm link wildglob done.');
        done();
      });
    });
  },

  after: function() {
    this.timeout(600 * 1000);
    console.log('Cleaning up', this.target);
    rimraf.sync(this.target);
    console.log('Done');
  },

  'bash timing': function(done) {
    this.timeout(600 * 1000);
    console.log();
    console.log('Bash timing:');
    runBash('time bash -c \'shopt -s globstar; echo **/*.txt | wc -w\'', { cwd: this.target }, done);
  },

  'statSync and readdirSync timing': function(done) {
    this.timeout(600 * 1000);
    console.log();
    console.log('statSync and readdirSync timing:');
    runBash('time node -e \'' +
    ['var fs=require("fs");',
      'var count = 0;',
      'function walk (path) {',
      '  if (path.slice(-4) === ".txt") count++;',
      '  var stat = fs.statSync(path);',
      '  if (stat.isDirectory()) {',
      '    fs.readdirSync(path).forEach(function(entry) {',
      '      walk(path + "/" + entry);',
      '    })',
      '  }',
      '}',
      'walk(".");',
      'console.log(count)'
    ].join('\n') + '\'', { cwd: this.target }, done);
  },

  'glob.sync timing': function(done) {
    this.timeout(600 * 1000);
    console.log();
    console.log('glob.sync timing:');
    runBash('time node -e \'' +
    ['var glob=require("glob");',
      'console.log(glob.sync("**/*.txt").length);'
    ].join('\n') + '\'', { cwd: this.target }, done);
  },

  'wildglob.sync timing (minimatch)': function(done) {
    this.timeout(600 * 1000);
    console.log();
    console.log('wildglob.sync (minimatch) timing:');
    runBash('time node -e \'' +
    ['var glob=require("wildglob");',
      'console.log(glob.sync("**/*.txt").length);'
    ].join('\n') + '\'', { cwd: this.target }, done);
  },

  'wildglob.sync timing (wildmatch)': function(done) {
    this.timeout(600 * 1000);
    console.log();
    console.log('wildglob.sync (wildmatch) timing:');
    runBash('time node -e \'' +
    ['var glob=require("wildglob"),',
      '    wildmatch = require("wildmatch");',
      'console.log(glob.sync("**/*.txt", { ',
      '   match: function(filepath, pattern) { ',
      '     return wildmatch(filepath, pattern, { pathname: true });',
      ' }',
      '}).length);'
    ].join('\n') + '\'', { cwd: this.target }, done);
  },

  'wildglob.sync timing (globy)': function(done) {
    this.timeout(600 * 1000);
    console.log();
    console.log('wildglob.sync (globy) timing:');
    runBash('time node -e \'' +
    ['var glob=require("wildglob"),',
      '    globy = require("globy");',
      'console.log(glob.sync("**/*.txt", { ',
      '   match: function(filepath, pattern) { ',
      '     return globy.fnmatch(pattern, filepath);',
      ' }',
      '}).length);'
    ].join('\n') + '\'', { cwd: this.target }, done);
  },

  'wildglob.sync timing (NOP)': function(done) {
    this.timeout(600 * 1000);
    console.log();
    console.log('wildglob.sync (NOP) timing:');
    runBash('time node -e \'' +
    ['var glob=require("wildglob");',
      'console.log(glob.sync("**/*.txt", { ',
      '   match: function(filepath, pattern) { ',
      '     return true;',
      ' }',
      '}).length);'
    ].join('\n') + '\'', { cwd: this.target }, done);
  },

  'wildglob.async timing (minimatch)': function(done) {
    this.timeout(600 * 1000);
    console.log();
    console.log('wildglob.async timing (minimatch):');
    runBash('time node -e \'' +
    ['var glob=require("wildglob");',
      'glob("**/*.txt", function (er, files) {',
      '  console.log(files.length)',
      '});'
    ].join('\n') + '\'', { cwd: this.target }, done);
  },


  'glob.async timing': function(done) {
    this.timeout(600 * 1000);
    console.log();
    console.log('Node glob.async timing:');
    runBash('time node -e \'' +
    ['var glob=require("glob");',
      'glob("**/*.txt", function (er, files) {',
      '  console.log(files.length)',
      '});'
    ].join('\n') + '\'', { cwd: this.target }, done);
  }

  // wildglob - glob.js
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
