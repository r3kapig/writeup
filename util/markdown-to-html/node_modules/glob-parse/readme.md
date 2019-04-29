# glob-parse

Returns a parsed representation of a glob string; does not require [Minimatch](https://github.com/isaacs/minimatch).

## Features

- Works on any string, does not require [Minimatch](https://github.com/isaacs/minimatch) or any other separate glob library.
- Does not perform glob matching: it just parses a glob expression into segments and produces relevant metadata about those segments.
- Pure parsing/tokenization is useful for working with glob expressions. For example:

[wildglob](https://github.com/mixu/wildglob) uses `glob-parse` to parse the different segments of the input glob and then combines the string segments to determine where to start glob matching.

[glob2base](https://github.com/wearefractal/glob2base) extracts a base path from a glob. It uses Minimatch to do this, but `glob-parse` (the `.basename()` function) can also be used to extract the base path from a glob.

## API and examples

### Basic parsing

````js
var parse = require('glob-parse');
console.log(parse('js/*.js'));
// [ 'js/', '*', '.js' ]
console.log(parse('js/**/test/*.js'));
// [ 'js/', '**', '/test/', '*', '.js' ]
````

### .basename()

`basename()` works like `glob2base`:

````js
console.log(parse.basename('js/test{0..9}/*.js'));
// js/
console.log(parse.basename('js/t+(wo|est)/*.js'));
// js/
console.log(parse.basename('lib/{components,pages}/**/{test,another}/*.txt'));
// lib/
````


### Full type annotations

Pass { full: true } to return the token type annotations.

````js
console.log(parse('js/t[a-z]st/*.js', { full: true }));
// { parts: [ 'js/t', '[a-z]', 'st/', '*', '.js' ],
//   types: [ 'str', 'set', 'str', '*', 'str' ] }

console.log(parse('js/{src,test}/*.js', { full: true }));
// { parts: [ 'js/', '{src,test}', '/', '*', '.js' ],
//   types: [ 'str', 'brace', 'str', '*', 'str' ] }

console.log(parse('test/+(a|b|c)/a{/,bc*}/**', { full: true }));
// { parts: [ 'test/', '+(a|b|c)', '/a', '{/,bc*}', '/', '**' ],
//   types: [ 'str', 'ext', 'str', 'brace', 'str', '**' ] }
````
