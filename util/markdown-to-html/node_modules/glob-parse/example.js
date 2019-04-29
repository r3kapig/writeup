var parse = require('./index.js');

    // basic parsing

    console.log(parse('js/*.js'));
    console.log(parse('js/**/test/*.js'));

    // pass { full: true } to return the token type annotations

    console.log(parse('js/t[a-z]st/*.js', { full: true }));
    console.log(parse('js/{src,test}/*.js', { full: true }));
    console.log(parse('test/+(a|b|c)/a{/,bc*}/**', { full: true }));


    console.log(parse.basename('js/test{0..9}/*.js'));
    console.log(parse.basename('js/t+(wo|est)/*.js'));
    console.log(parse.basename('lib/{components,pages}/**/{test,another}/*.txt'));
