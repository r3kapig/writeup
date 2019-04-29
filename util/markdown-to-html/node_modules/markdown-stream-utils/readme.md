# markdown-stream-utils

Utility functions for processing markdown files using object mode streams. Used by [markdown-styles](https://github.com/mixu/markdown-styles) and by [ghost-render](https://github.com/mixu/ghost-render).

## Changelog

`v1.2.0`: Updated highlight.js and other dependencies, thanks @omnibs!

`v1.1.0`: made `highlight` apply the syntax highlighting for the specific language if available in highlight.js. Added `md.marked` and added `opts` to `md.convertMd()`.

# API

## Getting started

All of the `markdown-stream-utils` functions expect to receive objects representing each markdown file. The files should have three properties:

- `path`: a path to the original filename
- `stat`: fs.stats object
- `contents`: the contents of the file as a string

Here's a full example of using `markdown-stream-utils`, with some helpers from `[pipe-iterators](https://github.com/mixu/pipe-iterators)`:


```js
var pi = require('pipe-iterators'),
    md = require('markdown-stream-utils');

pi.fromArray([ __dirname + '/foo.md', __dirname + '/bar.md' ])
  .pipe(pi.thru.obj(function(file, enc, onDone) {
    var stat = fs.statSync(file);
    if (stat.isFile()) {
      this.push({
        path: file,
        stat: stat,
        contents: fs.readFileSync(file).toString()
      });
    }
    onDone();
  }))
  .pipe(md.parseHeader())
  .pipe(md.parseMd())
  .pipe(md.highlightJS())
  .pipe(md.convertMd())
  .pipe(pi.toArray(function(results) {
    console.log(results);
  }));
```

## parseHeader()

```js
.pipe(md.parseHeader())
```

Parses header sections in markdown files. For example, given a object with the following `content` field:

```
title: Hello world
author: foo
---
# Heading
...
```

it will augment the existing object with two new fields: `title` and `author` with the specified values.

The header section may be written in either JSON or YAML. There must be at least three `-` characters that separate the header from the rest of the content (on a single line). Headers may also have a beginning delimiter, e.g.:

```
---
title: Hello world
---
# Heading
```

The header section will be removed from `contents`, so that only the markdown content after the `---` will be kept in the `contents` key.

You can customize the `contents` field as well as the destination of the metadata. To set the contents field name, pass in an options hash with `contentsKey`. To set the metadata storage key, pass the key name in `metadataKey`; if this is false (default), the metadata is merged; if it is set then the metadata is stored under a subkey.

## parseMd()

```js
pipe(md.parseMd())
```

Given an object with a `contents` field, executes `marked.lexer()` on the contents field. The new value is the lexer tree from `marked`.

## highlight()

```js
pipe(md.highlight())
```

Iterates over the lexer tree from `parseMd`, and executes the highlight.js highlighter on each code block.

You can add support for additional languages by passing a custom callback with the signature `function(code, lang) {}`, which should return either a HTML string containing the highlighted version of the code, or `false` if you want to run highlight.js on the code block.

Note that you will need a highlight.js CSS style sheet in your final output so that the styling is visible.

## annotateMdHeadings()

```js
pipe(md.annotateMdHeadings())
```

Iterates over the lexer tree from `parseMd`. Annotates every heading with an id, so that when converted to HTML the headings can be targeted via links. An array all the headings is produced under `headings`. The value is an array of lexer tokens with an `id` property.

For example:

```
# Test
foo
```

results in the input object being augmented with:

```
{ headings: [ { id: 'test', text: 'foo', type: 'heading', depth: 1 } ] }
```

By default, the markdown tokens are read from the `contents` key on the input object, and written to the `headings` key.

You can customize the keys used by passing in an options hash. The `contentsKey` property controls the key from which the lexer tree is read, and the `headingsKey` controls the key to which the headings are written.

## convertMd(opts)

```js
pipe(md.convertMd())
```

Constructs a new parser using `marked` default options, overriding with the values from `opts` where specified (e.g. `opts.renderer` can be used to override the renderer).

Given an object with a `contents` field, executes `Parser.parse()` on the contents field. The new value is the HTMLs from `marked`.

## marked

```js
console.log(md.marked);
```

A reference to the `marked` library, in case you need to construct a marked.Renderer for convertMd.
