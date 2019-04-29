var microee = require('microee'),
    ondone = require('ondone');

// setTimeout is very problematic since it consumes some resources on each invocation
// and cannot be optimized like process.nextTick
// Node 10.x: prefer setImmediate over nextTick
// IE10 dislikes direct assignment (https://github.com/caolan/async/pull/350)
var delay = (typeof setImmediate === 'function' ? function (fn) { setImmediate(fn); } :
    (process && typeof process.nextTick === 'function' ? process.nextTick : setTimeout));

function Parallel(limit) {
  this.limit = limit || Infinity;
  this.running = 0;
  this.tasks = [];
  this.maxStack = 50;
}

microee.mixin(Parallel);

Parallel.prototype.isFull = function() {
  return this.running >= this.limit;
};

Parallel.prototype.isEmpty = function() {
  return this.running === 0 && this.tasks.length === 0;
};

Parallel.prototype.exec = function(tasks, onDone) {
  if(!tasks || (Array.isArray(tasks) && tasks.length === 0)) {
   if (this.isEmpty()) {
    this.emit('empty');
   }
   onDone && onDone();
    return this;
  }

  if (onDone) {
    tasks = ondone(tasks, onDone);
  }

  this.tasks = this.tasks.concat(tasks);
  this._next(1);
  return this;
};

Parallel.prototype._next = function(depth) {
  // if nothing is running and the queue is empty, emit empty
  if(this.isEmpty()) {
    this.emit('empty');
  }
  while(!this.isFull() && this.tasks.length > 0) {
    this.running++;
    this._runTask(this.tasks.shift(), depth + 1);
  }
};

Parallel.prototype._runTask = function(task, depth) {
  var self = this;

  function run() {
    task(function(err) {
      self.running--;
      if (err) {
        return self.emit('error', err, task);
      }
      self.emit('done', task);
      self._next(depth);
    });
  }

  // avoid issues with deep recursion
  if (depth > this.maxStack) {
    depth = 0;
    delay(run, 0);
  } else {
    run();
  }
};

module.exports = function(limit, tasks, onDone) {
  var p = new Parallel(limit);
  // tasks must run after the return has completed
  delay(function() { p.exec(tasks, onDone); });
  return p;
};
