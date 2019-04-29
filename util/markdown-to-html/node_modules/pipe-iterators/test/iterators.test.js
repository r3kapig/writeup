var assert = require('assert'),
    pi = require('../index.js'),
    isReadable = require('../lib/is-stream').isReadable,
    isWritable = require('../lib/is-stream').isWritable,
    isDuplex = require('../lib/is-stream').isDuplex;

describe('forEach', function() {

  var stream, calls, contexts;

  beforeEach(function() {
    calls = [];
    contexts = [];
    stream = pi.fromArray(['a', 'b', 'c']);
  });

  it('iterates over every element with expected arguments', function(done) {
    stream.pipe(pi.forEach(function(obj, index) {
        contexts.push(this);
        calls.push([ obj, index]);
      }))
      .pipe(pi.toArray(function(results) {
        assert.deepEqual(calls, [
          [ 'a', 0 ],
          [ 'b', 1 ],
          [ 'c', 2 ]
        ]);
        assert.deepEqual(results, [ 'a', 'b', 'c' ]);
        done();
      }));
  });

  it('uses the provided thisArg', function(done) {
    var context = { foo: 'bar' };
    stream.pipe(pi.forEach(function(obj, index) {
        contexts.push(this);
        calls.push([ obj, index]);
      }, context))
      .pipe(pi.toArray(function(results) {
        assert.ok(contexts.every(function(item) {
          return item === context;
        }));
        assert.deepEqual(calls, [
          [ 'a', 0 ],
          [ 'b', 1 ],
          [ 'c', 2 ]
        ]);
        assert.deepEqual(results, [ 'a', 'b', 'c' ]);
        done();
      }));
  });
});

describe('map', function() {

  var stream, calls, contexts;

  beforeEach(function() {
    calls = [];
    contexts = [];
    stream = pi.fromArray(['a', 'b', 'c']);
  });

  it('should apply a mapper', function(done) {
    stream.pipe(pi.map(function(obj, index) {
        contexts.push(this);
        calls.push([ obj, index]);
        return obj.toString().toUpperCase();
      }))
      .pipe(pi.toArray(function(results) {
        assert.deepEqual(calls, [
          [ 'a', 0 ],
          [ 'b', 1 ],
          [ 'c', 2 ]
        ]);
        assert.deepEqual(results, [ 'A', 'B', 'C' ]);
        done();
      }));
  });

  it('uses the provided thisArg', function(done) {
    var context = { foo: 'bar' };
    stream.pipe(pi.map(function(obj, index) {
        contexts.push(this);
        calls.push([ obj, index]);
        return obj.toString().toUpperCase();
      }, context))
      .pipe(pi.toArray(function(results) {
        assert.ok(contexts.every(function(item) {
          return item === context;
        }));
        assert.deepEqual(calls, [
          [ 'a', 0 ],
          [ 'b', 1 ],
          [ 'c', 2 ]
        ]);
        assert.deepEqual(results, [ 'A', 'B', 'C' ]);
        done();
      }));
  });
});


describe('reduce', function() {

  var stream, calls;

  beforeEach(function() {
    calls = [];
    stream = pi.fromArray([1, 2, 3]);
  });

  it('accumulates results', function(done) {
    stream.pipe(pi.reduce(function(prev, curr, index) {
        calls.push([ prev, curr, index ]);
        return prev + curr;
      }, 4))
      .pipe(pi.toArray(function(results) {
        assert.deepEqual(calls, [
          [ 4, 1, 0 ],
          [ 5, 2, 1 ],
          [ 7, 3, 2 ]
        ]);
        assert.deepEqual(results, [ 10 ]);
        done();
      }));
  });

  // If the stream has only one element and no `initialValue` was provided,
  // or if `initialValue` is provided but the stream is empty, the solo
  // value would be returned without calling callback.

  it('works when initial is not set', function(done) {
    stream.pipe(pi.reduce(function(prev, curr, index) {
        calls.push([ prev, curr, index]);
        return prev + curr;
      }))
      .pipe(pi.toArray(function(results) {
        assert.deepEqual(calls, [
          [ 1, 2, 1 ],
          [ 3, 3, 2 ]
        ]);
        assert.deepEqual(results, [ 6 ]);
        done();
      }));
  });
});


describe('filter', function() {

  var stream, calls, contexts;

  beforeEach(function() {
    calls = [];
    contexts = [];
    stream = pi.fromArray([1, 2, 3]);
  });

  it('filters out non-matching values', function(done) {
    stream.pipe(pi.filter(function(obj, index) {
        contexts.push(this);
        calls.push([ obj, index]);
        return obj % 2 == 0;
      }))
      .pipe(pi.toArray(function(results) {
        assert.deepEqual(calls, [
          [ 1, 0 ],
          [ 2, 1 ],
          [ 3, 2 ]
        ]);
        assert.deepEqual(results, [ 2 ]);
        done();
      }));
  });

  it('uses the provided thisArg', function(done) {
    var context = { foo: 'bar' };
    stream.pipe(pi.filter(function(obj, index) {
        contexts.push(this);
        calls.push([ obj, index]);
        return obj % 2 == 0;
      }, context))
      .pipe(pi.toArray(function(results) {
        assert.ok(contexts.every(function(item) {
          return item === context;
        }));
        assert.deepEqual(calls, [
          [ 1, 0 ],
          [ 2, 1 ],
          [ 3, 2 ]
        ]);
        assert.deepEqual(results, [ 2 ]);
        done();
      }));
  });
});

describe('mapKey', function() {

  var stream, calls, contexts, context = { foo: 'bar' };

  beforeEach(function() {
    calls = [];
    contexts = [];
    stream = pi.fromArray([
        { a: 'aBc', b: 'dEf' },
        { a: 'gHi', b: 'jKl' },
        {}
      ]);
  });

  it('maps with a string and a function', function(done) {
    var objs = [];
    stream.pipe(pi.mapKey('a', function(value, obj, index) {
        contexts.push(this);
        objs.push(obj);
        calls.push([ value, index]);
        return ('' + value).toUpperCase();
      }, context))
      .pipe(pi.toArray(function(results) {
        assert.ok(contexts.every(function(item) {
          return item === context;
        }));
        assert.ok(objs.every(function(item, index) {
          return item === results[index];
        }));
        assert.deepEqual(calls, [
          [ 'aBc', 0 ],
          [ 'gHi', 1 ],
          [ undefined, 2 ]
        ]);
        assert.deepEqual(results, [
          { a: 'ABC', b: 'dEf' },
          { a: 'GHI', b: 'jKl' },
          { a: 'UNDEFINED' }
        ]);
        done();
      }));
  });

  it('maps with a hash of functions and non-functions', function(done) {
    var objs = [];
    stream.pipe(pi.mapKey({
      a: function(value, obj, index) {
        contexts.push(this);
        objs.push(obj);
        calls.push([ value, index]);
        return ('' + value).toUpperCase();
      },
      // bool, str, obj, arr, null, undefined
      b: true,
      c: 'str',
      d: { foo: 'bar' },
      e: [ 'a' ],
      f: null,
      e: undefined
    }, context))
      .pipe(pi.toArray(function(results) {
        assert.ok(contexts.every(function(item) {
          return item === context;
        }));
        assert.ok(objs.every(function(item, index) {
          return item === results[index];
        }));
        assert.deepEqual(calls, [
          [ 'aBc', 0 ],
          [ 'gHi', 1 ],
          [ undefined, 2 ]
        ]);
        assert.deepEqual(results, [
          { a: 'ABC', b: true, c: 'str', d: { foo: 'bar' }, e: [ 'a' ], f: null, e: undefined },
          { a: 'GHI', b: true, c: 'str', d: { foo: 'bar' }, e: [ 'a' ], f: null, e: undefined },
          { a: 'UNDEFINED', b: true, c: 'str', d: { foo: 'bar' }, e: [ 'a' ], f: null, e: undefined }
        ]);
        done();
      }));
  });
});
