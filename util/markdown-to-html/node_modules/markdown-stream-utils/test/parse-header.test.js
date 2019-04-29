var assert = require('assert'),
    fs = require('fs'),
    pi = require('pipe-iterators'),
    glob = require('wildglob'),
    fixture = require('file-fixture'),
    md = require('../'),
    read = require('./read');

describe('parse header tests', function() {
  function render(dir, done) {
    glob.stream(dir + '/*')
        .pipe(read())
        .pipe(md.parseHeader())
        .pipe(md.parseMd())
        .pipe(pi.toArray(done));
  }

  it('parses a ---- ... ---- delimited header', function(done) {
    var dir = fixture.dir({
      'foo.md': [
        '----',
        'title: Hello world',
        'author: Anonymous',
        '----',
        '# Test',
        'abcdef'
      ].join('\n')
    });

    render(dir, function(results) {
      assert.equal(results[0].title, 'Hello world');
      assert.equal(results[0].author, 'Anonymous');
      done();
    });
  });

  it('parses a header with just the ending ---- delimiter', function(done) {
    var dir = fixture.dir({
      'foo.md': [
        'title: Hello world',
        'author: Anonymous',
        '----',
        '# Test',
        'abcdef'
      ].join('\n')
    });

    render(dir, function(results) {
      assert.equal(results[0].title, 'Hello world');
      assert.equal(results[0].author, 'Anonymous');
      done();
    });
  });

  it('parses a JSON header', function(done) {
    var dir = fixture.dir({
      'foo.md': [
        JSON.stringify({
          string: 'hello world',
          arr: [ 'A', 'B', 'C'],
          hash: { foo: 'bar' },
          date: '2002-12-14'
        }, null, 2),
        '----',
        '# Test',
        'abcdef'
      ].join('\n')
    });

    render(dir, function(results) {
      assert.equal(results[0].string, 'hello world');
      assert.deepEqual(results[0].arr, [ 'A', 'B', 'C' ]);
      assert.deepEqual(results[0].hash, { foo: 'bar' });
      assert.equal(results[0].date, '2002-12-14');
      done();
    });
  });

  it('parses a YAML header', function(done) {
    var dir = fixture.dir({
      'foo.md': [
        '---',
        'string: hello world',
        'arr:',
        ' - A',
        ' - B',
        ' - C',
        'hash: { foo: bar }',
        'date: 2002-12-14',
        '----',
        '# Test',
        'abcdef'
      ].join('\n')
    });

    render(dir, function(results) {
      assert.equal(results[0].string, 'hello world');
      assert.deepEqual(results[0].arr, [ 'A', 'B', 'C' ]);
      assert.deepEqual(results[0].hash, { foo: 'bar' });
      assert.ok(results[0].date instanceof Date);
      assert.equal(results[0].date.getTime(), 1039824000000);
      done();
    });

  });

  it('doesn\'t crash and burn on an invalid delimited header', function(done) {
    var dir = fixture.dir({
      'foo.md': [
        'string hello world',
        'arr:',
        ' - A',
        ' - B',
        ' - C',
        'hash: { foo: bar',
        '----',
        '# Test',
        'abcdef'
      ].join('\n')
    });

    render(dir, function(results) {
      done();
    });
  });

  it('can customize the `contents` field name', function(done) {
    pi.fromArray([
      { text: [
        '----',
        'title: Hello world',
        'author: Anonymous',
        '----',
        '# Test'
        ].join('\n')
      }
      ])
        .pipe(md.parseHeader({ contentsKey: 'text' }))
        .pipe(pi.toArray(function(results) {
          assert.equal(results[0].title, 'Hello world');
          assert.equal(results[0].author, 'Anonymous');
          done();
        }));
  });

  it('can customize the `metadata` storage key', function(done) {
    pi.fromArray([
      { contents: [
        '----',
        'title: Hello world',
        'author: Anonymous',
        '----',
        '# Test'
        ].join('\n')
      }
      ])
        .pipe(md.parseHeader({ metadataKey: 'meta' }))
        .pipe(pi.toArray(function(results) {
          assert.equal(results[0].meta.title, 'Hello world');
          assert.equal(results[0].meta.author, 'Anonymous');
          done();
        }));

  });

});

