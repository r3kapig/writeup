var assert = require('assert'),
    pi = require('../index.js'),
    isReadable = require('../lib/is-stream').isReadable,
    isWritable = require('../lib/is-stream').isWritable,
    isDuplex = require('../lib/is-stream').isDuplex,
    child_process = require('child_process');

describe('fromArray', function() {

  it('returns a readable stream with the array contents', function(done) {
    var stream = pi.fromArray(1, 2, 3);
    assert.ok(isReadable(stream));
    stream.pipe(pi.toArray(function(contents) {
      assert.deepEqual(contents, [ 1, 2, 3 ]);
      done();
    }));
  });

});

describe('toArray', function() {

  it('returns a writable stream', function() {
    var stream = pi.toArray();
    assert.ok(isWritable(stream));
  });

  it('accepts an optional callback on end', function(done) {
    var stream = pi.toArray(function(contents) {
      assert.deepEqual(contents, [ 1, 2, 3 ]);
      done();
    });
    pi.fromArray(1, 2, 3).pipe(stream);
  });

  it('accepts an array as a target', function(done) {
    var result = [],
        stream = pi.toArray(result);
    pi.fromArray(1, 2, 3).pipe(stream).once('finish', function() {
      assert.deepEqual(result, [ 1, 2, 3 ]);
      done();
    });
  });
});


describe('devnull', function() {

  it('returns a writable stream which consumes every element', function() {
    var result = pi.devnull();
    assert.ok(isWritable(result));
    assert.ok(!isReadable(result));
  });

  it('call an optional callback on end', function(done) {
    var result = pi.devnull(done);
    pi.fromArray(1).pipe(result);
  });
});

describe('combine', function() {

  it('throws an error if the first argument is not a readable stream', function() {
    assert.throws(function() {
      var result = pi.combine(pi.toArray(), pi.toArray());
    });
  });

  it('throws an error if the last argument is not a writable stream', function() {
    assert.throws(function() {
      var result = pi.combine(pi.fromArray(1), pi.fromArray(1));
    });
  });

  it('throws an error if the first and last streams are the same stream', function() {
    assert.throws(function() {
    var thru = pi.thru();
      var result = pi.combine(thru, thru);
    });
  });

  it('works with a child process object', function(done) {
    var p = child_process.spawn('wc', ['-c']),
        stream = pi.combine(p.stdin, p.stdout);

    assert.ok(isReadable(stream));
    assert.ok(isWritable(stream));
    assert.ok(isDuplex(stream));

    pi.fromArray('a', 'b', 'c')
      .pipe(stream)
      .pipe(pi.toArray(function(result) {
        assert.equal(result, 3);
        done()
      }));
  });

  it('listening on error captures errors emitted in the first stream', function(done) {
    var result = pi.combine(pi.thru.obj(function(chunk, enc, done) {
      this.emit('error', new Error('Expected error'));
      this.push(chunk);
      done();
    }), pi.thru.obj());

    result.once('error', function(err) {
      assert.ok(err);
      done();
    });
    pi.fromArray(1).pipe(result).pipe(pi.devnull());
  });

  it('listening on error captures errors emitted in the second stream', function(done) {
    // note that combine does NOT pipe the two streams together
    var writable = pi.through.obj();
    var readable = pi.through.obj(function(chunk, enc, done) {
      this.emit('error', new Error('Expected error'));
      this.push(chunk);
      done();
    });
    writable.pipe(readable);
    var result = pi.combine(writable, readable);

    result.once('error', function(err) {
      assert.ok(err);
      done();
    });

    pi.fromArray(1).pipe(result).pipe(pi.devnull());
  });

  // readable
  xit('emits the readable event when readable');
  xit('emits the data event when in push stream mode');
  xit('emits the end event when in push stream mode');
  xit('emits the close event when the input stream emits close');

  // writable
  xit('emits the finish event');
  xit('emits the drain event when drained');
  xit('emits the pipe event when piped to');
  xit('emits the unpipe event when unpiped from');
});
