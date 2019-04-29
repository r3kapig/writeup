var assert = require('assert'),
    pi = require('../index.js'),
    isReadable = require('../lib/is-stream').isReadable,
    isWritable = require('../lib/is-stream').isWritable,
    isDuplex = require('../lib/is-stream').isDuplex,
    child_process = require('child_process');

describe('match', function() {

  it('returns a writable stream, accepts multiple condition + stream pairs', function(done) {
    var twos = [],
        threes = [],
        result = pi.match(
          function(obj) { return obj % 2 == 0; },
          pi.toArray(twos),
          function(obj) { return obj % 3 == 0; },
          pi.toArray(threes),
          pi.devnull()
        );

    assert.ok(isWritable(result));
    assert.ok(!isReadable(result));

    pi.fromArray([ 1, 2, 3, 4, 5, 6 ])
      .pipe(result)
      .once('finish', function() {
        assert.deepEqual(twos, [ 2, 4, 6]);
        assert.deepEqual(threes, [ 3 ]); // matched in order
        done();
      });
  });

  it('works when given a single condition and stream', function(done) {
    var twos = [],
        result = pi.match(
          function(obj) { return obj % 2 == 0; },
          pi.toArray(twos),
          pi.devnull()
        );

    assert.ok(isWritable(result));
    assert.ok(!isReadable(result));

    pi.fromArray([ 1, 2, 3, 4, 5, 6 ])
      .pipe(result)
      .once('finish', function() {
        assert.deepEqual(twos, [ 2, 4, 6]);
        done();
      });
  });

  it('works when given a single stream (rest)', function(done) {
    var all = [],
        result = pi.match(
          pi.toArray(all)
        );

    assert.ok(isWritable(result));
    assert.ok(!isReadable(result));

    pi.fromArray([ 1, 2, 3, 4, 5, 6 ])
      .pipe(result)
      .once('finish', function() {
        assert.deepEqual(all, [ 1, 2, 3, 4, 5, 6 ]);
        done();
      });
  });

  it('accepts a last parameter which is a stream for non-matching elements', function(done){
    var twos = [],
        threes = [],
        rest = [],
        result = pi.match(
          function(obj) { return obj % 2 == 0; },
          pi.toArray(twos),
          function(obj) { return obj % 3 == 0; },
          pi.toArray(threes),
          pi.toArray(rest)
        );

    assert.ok(isWritable(result));
    assert.ok(!isReadable(result));

    pi.fromArray([ 1, 2, 3, 4, 5, 6 ])
      .pipe(result)
      .once('finish', function() {
        assert.deepEqual(twos, [ 2, 4, 6]);
        assert.deepEqual(threes, [ 3 ]); // matched in order
        assert.deepEqual(rest, [ 1, 5]);
        done();
      });
  });

  function errorStream() {
    return pi.thru.obj(function(chunk, enc, done) {
      this.emit('error', new Error('Expected error'));
      this.push(chunk);
      done();
    });
  }
  function always() { return true; }
  function never() { return false; }

  it('listening on error captures errors emitted in the first stream', function(done) {
    var stream = pi.match(always, errorStream(), never, pi.thru.obj(), pi.thru.obj());
    stream.once('error', function(err) {
      assert.ok(err);
      done();
    });

    pi.fromArray(1).pipe(stream);
  });

  it('listening on error captures errors emitted in the second stream', function(done) {
    var stream = pi.match(never, pi.thru.obj(), always, errorStream(), pi.thru.obj());
    stream.once('error', function(err) {
      assert.ok(err);
      done();
    });

    pi.fromArray(1).pipe(stream);
  });

  it('listening on error captures errors emitted in the rest stream', function(done) {
    var stream = pi.match(never, pi.thru.obj(), never, pi.thru.obj(), errorStream());
    stream.once('error', function(err) {
      assert.ok(err);
      done();
    });

    pi.fromArray(1).pipe(stream);
  });

});

describe('fork', function() {

  it('returns a duplex stream', function() {
    var result = pi.fork();
    assert.ok(isWritable(result));
    assert.ok(isReadable(result));
  });

  it('prevents streams from interfering with each other by cloning', function(done) {
    var inputs = [ { id: 1 }, { id: 2 } ],
        result1 = [],
        result2 = [];
    pi.fromArray(inputs)
      .pipe(pi.fork(
        pi.head(pi.mapKey('foo', function() { return 'bar'; }), pi.toArray(result1)),
        pi.head(pi.mapKey('id', function(val) { return val * 2; }), pi.toArray(result2))
      )).once('finish', function() {
        assert.deepEqual(result1, [ { id: 1, foo: 'bar'}, { id: 2, foo: 'bar' }]);
        assert.deepEqual(result2, [ { id: 2 }, { id: 4 }]);
        done();
      });
  });
});

describe('merge', function() {

  it('returns a duplex stream', function() {
    assert.ok(isDuplex(pi.merge()));
  });

  it('merges multiple streams', function(done) {
    pi.merge(pi.fromArray(1, 2), pi.fromArray(3, 4), pi.fromArray(5, 6))
      .pipe(pi.toArray(function(result) {
        assert.deepEqual(result.sort(), [ 1, 2, 3, 4, 5, 6 ]);
        done();
      }));
  });

  it('merges multiple streams, arg is array', function(done) {
    pi.merge([pi.fromArray(1, 2), pi.fromArray(3, 4), pi.fromArray(5, 6)])
      .pipe(pi.toArray(function(result) {
        assert.deepEqual(result.sort(), [ 1, 2, 3, 4, 5, 6 ]);
        done();
      }));
  });


  it('works with just one stream', function(done) {
    pi.merge(pi.fromArray(1))
      .pipe(pi.toArray(function(result) {
        assert.deepEqual(result.sort(), [ 1 ]);
        done();
      }));
  });

  it('works with one empty stream', function(done) {
    pi.merge(pi.fromArray(1), pi.fromArray(), pi.fromArray(2))
      .pipe(pi.toArray(function(result) {
        assert.deepEqual(result.sort(), [ 1, 2 ]);
        done();
      }));
  });

  it('works with just empty streams', function(done) {
    pi.merge(pi.fromArray(), pi.fromArray())
      .pipe(pi.toArray(function(result) {
        assert.deepEqual(result.sort(), []);
        done();
      }));
  });

  it('works in flowing mode', function(done) {
    var result = [];
    pi.merge(pi.fromArray(1, 2), pi.fromArray(3, 4), pi.fromArray(5, 6))
      .on('data', function(data) { result.push(data); })
      .once('end', function() {
        assert.deepEqual(result.sort(), [ 1, 2, 3, 4, 5, 6]);
        done();
      });
  });

});

function logEvts(id, stream) {
  // readable (non-flowing) stream
  return stream.on('readable', function() {
    console.log('[' + id +'] "readable"');
  })
  .on('end', function() {
    console.log('[' + id +'] "end"');
  })
  .on('close', function() {
    console.log('[' + id +'] "close"');
  })
  .on('error', function(err) {
    console.log('[' + id +'] "error"', err);
  })
  // writable (non-flowing) stream
  .on('drain', function() {
    console.log('[' + id +'] "drain"');
  })
  .on('finish', function() {
    console.log('[' + id +'] "finish"');
  })
  .on('pipe', function() {
    console.log('[' + id +'] "pipe"');
  })
  .on('unpipe', function() {
    console.log('[' + id +'] "unpipe"');
  });
}

function logStream(id) {
  return logEvts(id, pi.thru.obj(function(data, enc, done) {
    console.log('[' + id + '] _transform ' + data);
    this.push(data);
    done();
  }, function(done) {
    console.log('[' + id +'] _flush');
    done();
  }));
}


describe('forkMerge', function() {

  function doubler(val) { return val * 2; }
  function add100(val) { return val + 100; }

  it('combines a fork stream and a merge stream', function(done) {

    pi.fromArray(1, 2, 3)
    .pipe(
       pi.forkMerge(
        pi.pipeline(pi.map(doubler), pi.map(doubler)),
        pi.pipeline(pi.map(add100), pi.map(add100))
      )
    ).pipe(pi.toArray(function(result) {
      assert.deepEqual(
        result.sort(function(a, b){ return a-b; }),
        [ 4, 8, 12, 201, 202, 203 ]
      );
      done();
    }))

  });

});

describe('matchMerge', function() {

  function add10(val) { return val + 10; }
  function add100(val) { return val + 100; }

  it('combines a match stream and a merge stream', function(done) {

    pi.fromArray([ 1, 2, 3, 4, 5, 6 ])
      .pipe(pi.matchMerge(
          function(obj) { return obj % 2 == 0; },
          pi.map(add10),
          function(obj) { return obj % 3 == 0; },
          pi.map(add100),
          pi.thru.obj()
        ))
      .pipe(pi.toArray(function(result) {


        assert.deepEqual(
          result.sort(function(a, b){ return a-b; }),
          [
            1, // 1 -> 1
            5, // 5 -> 5

            12, // 2 -> + 10 -> 12
            14, // 4 -> + 10 -> 14
            16, // 6 -> + 10 -> 16

            103 // 3 -> + 100 -> 103
          ]
        );
        done();
      }));
  });

});

describe('parallel', function() {

  it('can execute a series of tasks in serial order', function(done) {
    var calls = [];
    pi.fromArray(1, 2, 3)
      .pipe(pi.map(function(val, i) {
        calls.push(i);
        return function (done) {
          this.push(val * 2);
          done();
        };
      }))
      .pipe(pi.parallel(1))
      .pipe(pi.toArray(function(result) {
        assert.deepEqual(calls, [ 0, 1, 2]);
        assert.deepEqual(result, [ 2, 4, 6 ]);
        done();
      }));
  });

  it('can run the example', function(done) {
    pi.fromArray([
        function(done) { this.push(1); done(); },
        function(done) { this.push(2); done(); }
      ])
      .pipe(pi.parallel(2))
      .pipe(pi.toArray(function(result) {
        assert.deepEqual(result.sort(), [1, 2]);
        done();
      }));
  });

  it('can execute a series of tasks with parallelism 2', function(done) {
    pi.fromArray([
      function(done) {
        var self = this;
        setTimeout(function() {
          self.push(1);
          done();
        }, 50);
      },
      function(done) {
        var self = this;
        setTimeout(function() {
          self.push(2);
          done();
        }, 100);
      },
      function(done) {
        var self = this;
        setTimeout(function() {
          self.push(3);
          done();
        }, 25);
      }
    ])
      .pipe(pi.parallel(2))
      .pipe(pi.toArray(function(result) {
        assert.deepEqual(result, [ 1, 3, 2 ]); // due to timeouts
        done();
      }));
  });

  it('can execute a series of tasks with infinite parallelism', function(done) {
    pi.fromArray([
      function(done) {
        var self = this;
        setTimeout(function() {
          self.push(1);
          done();
        }, 50);
      },
      function(done) {
        var self = this;
        setTimeout(function() {
          self.push(2);
          done();
        }, 100);
      },
      function(done) {
        var self = this;
        setTimeout(function() {
          self.push(3);
          done();
        }, 25);
      }
    ])
      .pipe(pi.parallel(Infinity))
      .pipe(pi.toArray(function(result) {
        assert.deepEqual(result, [ 3, 1, 2 ]); // due to timeouts
        done();
      }));
  });

  it('works with empty', function(done) {
    pi.fromArray([])
      .pipe(pi.parallel(Infinity))
      .pipe(pi.toArray(function(result) {
        assert.deepEqual(result, [ ]);
        done();
      }));
  });

  it('add to parallel while executing', function(done) {
    var callOrder = [];

    // there are no guarantees that one "done" action runs
    // before another (unless you do parallelism = 1)
    function checkDone() {
      if (callOrder.length < 4) {
        return;
      }
      var expected = [ '1-1', '1-2', '2-2', '2-1' ];
      assert.ok(
        expected.every(function(item) { return callOrder.indexOf(item) > -1; }),
        'every callback should have run');

      done();
    }

    pi.fromArray([
      function a(done) {
        callOrder.push('1-1');
        done();
        // add more tasks
        this.write(function c(done) {
            setTimeout(function() {
              callOrder.push('2-1');
              done();
              checkDone();
            }, 20);
          });
        this.write(function d(done) {
            callOrder.push('2-2');
            done();
            checkDone();
          });
      },
      function b(done) {
        setTimeout(function() {
          callOrder.push('1-2');
          done();
          checkDone();
        }, 100);
      }
      ])
      .pipe(pi.parallel(1))
      .pipe(pi.devnull());

  });

});
