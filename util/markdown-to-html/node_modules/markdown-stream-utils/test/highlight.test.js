var assert = require('assert'),
    fs = require('fs'),
    pi = require('pipe-iterators'),
    glob = require('wildglob'),
    fixture = require('file-fixture'),
    md = require('../'),
    read = require('./read'),
    mdsCsv = require('mds-csv');

describe('highlighter test', function() {

  function render(dir, opts, done) {
    glob.stream(dir + '/*')
        .pipe(read())
        .pipe(md.parseMd())
        .pipe(md.highlight(opts))
        .pipe(md.convertMd())
        .pipe(pi.toArray(done));
  }


  it('can highlight any language supported by hl.js', function(done) {
    var dir = fixture.dir({
      'html.md': [
        '# Test',
        '```html',
        '<!DOCTYPE html>',
        '<title>Title</title>',
        '```'
      ].join('\n'),
      'js.md': [
        '# Test',
        '```js',
        'function $initHighlight(block, flags) { }',
        '```'
      ].join('\n'),
      'ruby.md': [
        '# Test',
        '```js',
        'class Zebra; def inspect; "X#{2 + self.object_id}" end end',
        '```'
      ].join('\n')
    });

    render(dir, null, function(results) {
      results.sort(function(a, b) { return a.path.localeCompare(b.path); });
      assert.equal(results[0].contents, [
        '<h1 id="test">Test</h1>',
        '<pre class="hljs"><code><span class="hljs-meta">&lt;!DOCTYPE html&gt;</span>',
        '<span class="hljs-tag">&lt;<span class="hljs-name">title</span>&gt;</span>Title<span class="hljs-tag">&lt;/<span class="hljs-name">title</span>&gt;</span></code></pre>'
      ].join('\n'));

      assert.equal(results[1].contents, [
        '<h1 id="test">Test</h1>',
        '<pre class="hljs"><code><span class="hljs-function"><span class="hljs-keyword">function</span> <span class="hljs-title">$initHighlight</span>(<span class="hljs-params">block, flags</span>) </span>{ }</code></pre>'
      ].join('\n'));

      assert.equal(results[2].contents, [
        '<h1 id="test">Test</h1>',
        '<pre class="hljs"><code><span class="hljs-class"><span class="hljs-keyword">class</span> <span class="hljs-title">Zebra</span></span>; def inspect; <span class="hljs-string">"X#{2 + self.object_id}"</span> end end</code></pre>'
      ].join('\n'));
      done();
    });
  });

  it('can highlight additional languages given a callback', function(done) {
    var dir = fixture.dir({
      'html.md': [
        '# Test',
        '```html',
        '<!DOCTYPE html>',
        '<title>Title</title>',
        '```'
      ].join('\n'),
      'csv.md': [
        '# Test',
        '```csv',
        'a,b,c',
        '```'
      ].join('\n')
    });

    render(dir, function(code, lang) {
      if (lang === 'csv') {
        return mdsCsv(code, lang);
      }
      return false;
    }, function(results) {
      results.sort(function(a, b) { return a.path.localeCompare(b.path); });
      assert.equal(results[0].contents, [
        '<h1 id="test">Test</h1>',
        '<pre class="hljs"><code><span class="hljs-keyword">a</span>,<span class="hljs-keyword">b</span>,<span class="hljs-keyword">c</span></code></pre>'
      ].join('\n'));
      assert.equal(results[1].contents, [
        '<h1 id="test">Test</h1>',
        '<pre class="hljs"><code><span class="hljs-meta">&lt;!DOCTYPE html&gt;</span>',
        '<span class="hljs-tag">&lt;<span class="hljs-name">title</span>&gt;</span>Title<span class="hljs-tag">&lt;/<span class="hljs-name">title</span>&gt;</span></code></pre>'
      ].join('\n'));

      done();
    });
  });
});
