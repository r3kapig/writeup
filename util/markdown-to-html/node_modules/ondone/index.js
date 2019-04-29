module.exports = function(tasks, onDone) {
  if (tasks) {
    tasks = (Array.isArray(tasks) ? tasks : [ tasks ]);
  }
  var triggered = false,
      calls = 0,
      total = (tasks ? tasks.length : 0);
  if (total === 0) {
    setTimeout(onDone, 0); // for cross-browser compatibility
    return [];
  }
  return tasks.map(function(task) {
    return function() {
      var done = arguments[arguments.length - 1],
          doneCalls = 0;
      if (triggered) { return done(); }
      task.apply(this, Array.prototype.slice.call(arguments, 0, -1).concat(function(err) {
        if (++doneCalls > 1) {
          throw new Error('"done" callback called more than once!');
        }
        // trigger the doneFn first, this makes nested ondone()'s complete as expected (inner first)
        if ((err || ++calls == total) && !triggered) {
          triggered = true;
          onDone(err);
        }
        done.apply(this, Array.prototype.slice.call(arguments));
      }));
    };
  });
};
