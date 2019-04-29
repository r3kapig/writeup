/*
'globstar-match.js - globstar should not have dupe matches': function() {
  // this test requires the pseudo streaming that is done and
  // tests that the results are equivalent, even if there is a risk for duplicate entries
  // due to branching in the globstar matching (at least in the way node-glob does it,
  // which is described here: https://github.com/isaacs/node-glob/issues/64
  // might not even be an issue with the less clever approach taken here
}

'new-glob-optional-options.js': {

  'new glob, with cb, and no options': function() {
    var result = glob(__filename).sort();
    console.log(result);
    assert.deepEqual(result, [__filename]);
  }
},
*/

// other cases:
// - mark.js: will probably not support { mark: true }
// - nocase-nomagic.js: not doing anything clever wrt. to case sensitivity so probably not needed
// - pause-resume.js: not going to support pausing once started
// - readme-issue.js: this is just a { mark: true } edge case
// - root / root.nomount: will probably not support { nomount: true }
// - stat.js: will not support { stat: true }
