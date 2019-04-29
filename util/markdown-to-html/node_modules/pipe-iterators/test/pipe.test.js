var assert = require('assert'),
    pi = require('../index.js'),
    isReadable = require('../lib/is-stream').isReadable,
    isWritable = require('../lib/is-stream').isWritable,
    isDuplex = require('../lib/is-stream').isDuplex;

describe('pipe function tests', function() {
  var dataEvents, endEvents;

  function getPassThrough() {
    return pi.through.obj(function(data, enc, done) {
      dataEvents.push(data);
      this.push(data);
      done();
    }, function(done) {
      endEvents++;
      done();
    });
  }

  beforeEach(function() {
    dataEvents = [];
    endEvents = 0;
  });

  describe('pipe', function() {

    it('constructs a pipe and returns an array', function(done) {
      var result = pi.pipe([
        getPassThrough(), getPassThrough()
      ]);

      assert.ok(Array.isArray(result));

      pi.fromArray([1, 2])
        .pipe(result[0])
        .pipe(pi.toArray(function(results) {
          assert.deepEqual(results, [ 1, 2 ]);
          assert.deepEqual(dataEvents, [ 1, 1, 2, 2]);
          assert.equal(endEvents, 2);
          done();
        }));
    });

    it('works when given a single array as an argument', function(done) {
      var result = pi.pipe([
        getPassThrough()
      ]);

      assert.ok(Array.isArray(result));

      pi.fromArray([1, 2])
        .pipe(result[0])
        .pipe(pi.toArray(function(results) {
          assert.deepEqual(results, [ 1, 2 ]);
          assert.deepEqual(dataEvents, [ 1, 2]);
          assert.equal(endEvents, 1);
          done();
        }));
    });

  });

  describe('head', function() {

    it('creates a pipe and returns the first element in the pipe', function(done) {
      var result = pi.head([
        getPassThrough(), getPassThrough()
      ]);

      assert.ok(!Array.isArray(result));
      assert.ok(isWritable(result) && isReadable(result));

      pi.fromArray([1, 2])
        .pipe(result)
        .pipe(pi.toArray(function(results) {
          assert.deepEqual(results, [ 1, 2 ]);
          assert.deepEqual(dataEvents, [ 1, 1, 2, 2]);
          assert.equal(endEvents, 2);
          done();
        }));
    });

    it('works when given a single array as an argument', function(done) {
      var result = pi.head([
        getPassThrough()
      ]);

      assert.ok(!Array.isArray(result));
      assert.ok(isWritable(result) && isReadable(result));

      pi.fromArray([1, 2])
        .pipe(result)
        .pipe(pi.toArray(function(results) {
          assert.deepEqual(results, [ 1, 2 ]);
          assert.deepEqual(dataEvents, [ 1, 2]);
          assert.equal(endEvents, 1);
          done();
        }));
    });

  });

  describe('tail', function() {

    it('creates a pipe and returns the lest element in the pipe', function(done) {
      var result = pi.tail([
        getPassThrough(), getPassThrough()
      ]);

      assert.ok(!Array.isArray(result));
      assert.ok(isWritable(result) && isReadable(result));

      pi.fromArray([1, 2])
        .pipe(result)
        .pipe(pi.toArray(function(results) {
          assert.deepEqual(results, [ 1, 2 ]);
          assert.deepEqual(dataEvents, [ 1, 2]);
          assert.equal(endEvents, 1);
          done();
        }));
    });

    it('works when given a single array as an argument', function(done) {
      var result = pi.tail([
        getPassThrough(),
      ]);

      assert.ok(!Array.isArray(result));
      assert.ok(isWritable(result) && isReadable(result));

      pi.fromArray([1, 2])
        .pipe(result)
        .pipe(pi.toArray(function(results) {
          assert.deepEqual(results, [ 1, 2 ]);
          assert.deepEqual(dataEvents, [ 1, 2]);
          assert.equal(endEvents, 1);
          done();
        }));
    });

  });

});

describe('pipeline', function() {

  it('throws an error if the first argument is not a readable stream', function() {
    assert.throws(function() {
      var result = pi.pipeline(pi.toArray(), pi.toArray());
    });
  });

  it('throws an error if the last argument is not a writable stream', function() {
    assert.throws(function() {
      var result = pi.pipeline(pi.fromArray(1), pi.fromArray(1));
    });
  });

  it('throws an error if the first and last streams are the same stream', function() {
    assert.throws(function() {
    var thru = pi.thru();
      var result = pi.pipeline(thru, thru);
    });
  });

  function doubler() {
    return pi.map(function(x) { return x*2; });
  }


  it('returns a duplex stream given a pipeline that ends with a duplex stream', function(done) {
    var stream = pi.pipeline(doubler(), doubler(), doubler());
    assert.ok(isDuplex(stream));

    // writes to the pipeline go to the first stream, reads from the pipeline come from last stream
    pi.fromArray(1, 2, 3)
      .pipe(stream)
      .pipe(pi.toArray(function(results) {
        assert.deepEqual(results, [ 8, 16, 24 ]);
        done();
      }));
  });

  it('returns a writable stream given a pipeline that ends with a writable stream', function(done) {
    var stream = pi.pipeline(doubler(), doubler(), pi.toArray(function(results) {
        assert.deepEqual(results, [ 4, 8, 12 ]);
        done();
      }));

    assert.ok(isWritable(stream));
    assert.ok(!isReadable(stream));
    // writes to the pipeline go to the first stream
    pi.fromArray(1, 2, 3).pipe(stream);
  });

  function errorStream() {
    return pi.thru.obj(function(chunk, enc, done) {
      this.emit('error', new Error('Expected error'));
      this.push(chunk);
      done();
    });
  }

  it('listening on error captures errors emitted in the first stream', function(done) {
    var stream = pi.pipeline(errorStream(), pi.thru.obj(), pi.thru.obj());
    stream.once('error', function(err) {
      assert.ok(err);
      done();
    });

    pi.fromArray(1).pipe(stream).pipe(pi.devnull());
  });

  it('listening on error captures errors emitted in the middle stream', function(done) {
    var stream = pi.pipeline(pi.thru.obj(), errorStream(), pi.thru.obj());
    stream.once('error', function(err) {
      assert.ok(err);
      done();
    });

    pi.fromArray(1).pipe(stream).pipe(pi.devnull());
  });


  it('listening on error captures errors emitted in the last stream', function(done) {
    var stream = pi.pipeline(pi.thru.obj(), pi.thru.obj(), errorStream());
    stream.once('error', function(err) {
      assert.ok(err);
      done();
    });

    pi.fromArray(1).pipe(stream).pipe(pi.devnull());
  });

});
