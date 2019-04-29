var wildmatch = require('wildmatch');



console.log('test/a/b', wildmatch('test/a/b', 'test/a/b/**'));

console.log('test/a/b/', wildmatch('test/a/b/', 'test/a/b/**'));
