var pi = require('./index.js');

pi.fromArray([{ a: 'a' }, { b: 'b' }, { c: 'c' }])
  .pipe(pi.mapKey('foo', function(value) { return typeof value === 'undefined' ? 'bar' : 'value'; }))
  .pipe(pi.forEach(function(obj) { console.log(obj); }));

pi.fromArray(['a', 'b', 'c'])
  .pipe(pi.map(function(chunk) { return chunk + '!!' }))
  .pipe(pi.forEach(function(obj) { console.log(obj); }));

pi.fromArray(['a', 'b', 'c'])
  .pipe(pi.reduce(function(prev, chunk) { return prev + '|' + chunk; }, ''))
  .pipe(pi.forEach(function(obj) { console.log(obj); }));

pi.fromArray([{ path: '/a/a' }, { path: '/a/b' }, { path: '/a/c' }])
  .pipe(pi.mapKey('path', function(p) { return p.replace('/a/', '/some/'); }))
  .pipe(pi.forEach(function(obj) { console.log(obj); }));
