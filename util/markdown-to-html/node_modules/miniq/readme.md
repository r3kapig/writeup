# miniq

miniq is yet another tiny async control flow library. It implements parallelLimit, with the ability to share the concurrency-limited queue.

## Changelog

`v1.0.1`: when given an empty tasks array, `empty` was not emitted.

`v1.0.0`: reduced the overall size by using [`ondone`](https://github.com/mixu/ondone) for the "wait to complete" functionality. Deprecated the `removeTasks()` and `concurrency()` methods. Added the `isFull` and `isEmpty` methods.

## Features

- small: miniq only implements `parallelLimit`
- can be used for all three basic control flow patterns
  - `series` = `parallel(1, tasks, onDone)`
  - `parallel` without a concurrency limit = `parallel(Infinity, tasks, onDone)`
  - `parallel` with a concurrency = default behavior
- no result passing: Many control flow libraries have a dozen variants which simply pass the result around in slightly different ways (e.g. `chain` vs. `map`). I'd rather just use JavaScript's scope rules to handle all those variants rather than have specialized functions for each thing.
- Node 10.x compatibility

miniq has one advanced feature, which is the ability to share the concurrency-limited queue among multiple different tasks. In other words, many different sets of operations can share the same queue and run limit. Each set of tasks can have it's own `onDone` function, but they share the same concurrency limit.

For example, if you are writing something that does a recursive directory traversal and does various (file system) operations, you can push all the operations into the same queue. This will allow you to limit (file system) concurrency across multiple operations.

## Installation

    npm install --save miniq

## API

`parallel(limit, tasks, [onDone])`:

- `limit` is a number which controls the maximum number of concurrent tasks. Set `limit = 1` for serial execution and `limit = Infinity` for unlimited parallelism.
- `onDone` is a callback `function(err) { ... }`; it is called when the tasks it is associated with have run
- `tasks` are callbacks `function(done) { ... }` which should call `done()` when they are complete.

The return value is an object with the following API:

- `.exec(tasks, [onDone])`: appends the new set of tasks and queues the `onDone` function once all of those tasks have completed.
- `isEmpty`: returns true if the queue is empty.
- `isFull`: returns true if the queue is currently running the maximum number of tasks.

## Some notes on Node 0.10.x (supported since `0.1.x`)

`miniq` uses `setImmediate` when available to break call stacks.

This is done by default in order to prevent stack overflows from occurring when executing in a tight loop. However, if your workload is already asynchronous, then you will never run into a call stack overflow since async calls break up the call stack.

The `.maxStack` property on the queue controls when a `setImmediate` / `nextTick` call is inserted. It is set to `50` by default, which seems to retain a good balance between call stack size and avoiding scheduling overhead.

 You should disable `maxStack` by setting it to `Infinity` if you know in advance that the work payloads are async and hence you will not need to occasionally break out of the call stack.

To set the `maxStack`, set it on the return value. For example:

    var queue = parallel(10, [ ... ], onDone);
    queue.maxStack = Infinity;

For maximum performance when operations are cheap (e.g. stat calls), set the queue `limit` to `Infinity` and the `maxStack` property to `Infinity`. This skips a lot of management overhead as all tasks are launched immediately and no stack breaks are inserted.

## Example: replacement for `parallelLimit`

    var parallel = require('miniq');

    parallel(10, [
      function(done) {
        fs.readFile(function(err, result) {
          if(err) {
            return done(err); // done takes one argument: the error
          }
        }
      },
    ], function(err) {
      // err is sent if any of the tasks returned an error
    });


## Example: replacement for `parallel`

    var parallel = require('miniq');

    parallel(Infinity, [
      function(done) { ... },
    ], function(err) {
      // err is sent if any of the tasks returned an error
    });

## Example: replacement for `series`

    var parallel = require('miniq');

    parallel(1, [
      function(done) { ... },
    ], function(err) {
      // err is sent if any of the tasks returned an error
    });

## Example: using miniq as a shared maximum-concurrency limited queue

    var parallel = require('miniq');

    function Foo() {
      this.queue = parallel(12);
    }

    Foo.prototype.bar = function() {
      this.queue.exec(tasks, function(err) { ... });
    };

    Foo.prototype.all = function() {
      // when the queue is empty
      this.queue.once('empty', function() {
        console.log('All done!');
      });

      this.queue.exec(tasks);
    };
